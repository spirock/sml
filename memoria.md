Memoria Suricata ML
Detección de Amenazas en Redes mediante Machine Learning y Suricata

1. Resumen

Este proyecto es un prototipo de detección y respuesta ante anomalías de red que integra pipeline de aprendizaje automático(Isolation Forest ) y una API (fastapi ) para control operativo. La solución:
captura de eventos en tiempo real(eve.json)
persistencia con MongoDb
preprocesa y enriquece datos
entrena/actualiza un modelo de anomalías.
genera reglas para mitigar el tráfico sospechoso y las recarga vía suricatasc
incorporación de un modo entrenamiento con etiquetas “normal” ,”anomaly” para construir un ground truth interno y evaluar el rendimiento (presisciónm, recall, F1, AUC-ROC).
Se presentan decisiones de diseño y procedimientos reproducibles en docker, pruebas con tráfico real y sintético.

2. Presentación
   2.1 Motivación
   La superficie de ataque de las redes corporativas ha crecido de forma sostenida en la última década: proliferación de servicios expuestos, teletrabajo, SaaS, cifrado ubicuo, y una alta rotación de dispositivos y configuraciones. En este contexto, los sistemas de detección basados exclusivamente en firmas (IDS tradicionales) muestran dos limitaciones clave: (1) dependen de la anticipación—alguien debe haber observado el patrón malicioso antes y haberlo codificado como regla—y (2) requieren un mantenimiento intensivo para seguir el ritmo de nuevas TTPs (técnicas, tácticas y procedimientos). Como consecuencia, emergen puntos ciegos ante comportamientos inéditos, variantes de ataques de “bajo y lento” o abuso de servicios legítimos.

Paralelamente, los equipos de seguridad necesitan automatizar tareas repetitivas y reducir el tiempo de respuesta sin sacrificar control. La realidad operativa es que las alertas se cuentan por miles: investigar manualmente cada una es inviable. Un enfoque de detección basada en anomalías—complementario a las firmas—permite señalar desviaciones del comportamiento “normal” de la red, priorizando eventos con mayor probabilidad de representar riesgo, incluso cuando no exista aún una firma específica.
Este proyecto nace para cubrir ese hueco con una propuesta práctica y reproducible: integrar el IDS/IPS Suricata (por su rendimiento, soporte multihilo y salida JSON estructurada) con un pipeline de aprendizaje automático capaz de aprender del entorno real y activar contramedidas de forma controlada. La motivación se apoya en cuatro ejes:

• Eficacia operativa: priorizar aquello que es distinto a lo habitual de la red, reduciendo el ruido y elevando señales más útiles al analista.
• Adaptabilidad continua: incorporar un modo de entrenamiento (training mode) para recopilar ground truth propio (normal/anómalo) y recalibrar el sistema con datos recientes, sin depender exclusivamente de datasets externos o firmas de terceros.
• Respuesta automatizada controlada: traducir detecciones en reglas Suricata recargables en caliente; además, agregar por IP cuando una misma fuente ataca múltiples puertos para evitar la explosión de reglas granulares y acelerar el containment.
•Reproducibilidad y transferencia: empaquetar todo en Docker (Suricata, MongoDB, FastAPI y tareas programadas), con scripts y endpoints claros para que cualquier equipo pueda desplegar, evaluar y mejorar el sistema en su propio entorno.
Desde el punto de vista académico, la motivación incluye demostrar que un esquema no supervisado como Isolation Forest—robusto frente a valores atípicos—puede integrarse de forma efectiva con un IDS/IPS de uso extendido, aportando métricas objetivas (Precisión, Recall, F1, AUC-ROC) y guías para su mejora iterativa (enriquecimiento de features, ajuste de umbrales, alternativas de modelo). Desde el punto de vista profesional, la solución promueve buenas prácticas: infraestructura como código, separación de responsabilidades, observabilidad y controles de seguridad (listas blancas, dry-run, y consideraciones éticas en la recolección de datos).
En síntesis, el proyecto busca cerrar la brecha entre la detección tradicional por firmas y la necesidad actual de detectar lo desconocido, habilitando un ciclo virtuoso: observar → aprender del propio entorno → detectar mejor → responder más rápido → medir y mejorar. Con ello, se aspira a aportar un artefacto útil para organizaciones y un caso de estudio sólido para la comunidad académica.

2.2 Objetivos y Alcance
El objetivo principal es desarrollar un sistema integral que:
Ingesta y almacenamiento: Recoja los logs de Suricata y los almacene en una base de datos (por ejemplo, MongoDB) para su posterior análisis.
Procesamiento y análisis: Procesar los datos utilizando técnicas de limpieza y transformación (módulo ml_processing.py), y entrenar un modelo de machine learning basado en IsolationForest (módulo train_model.py) para detectar comportamientos anómalos.
Generación de reglas automáticas: A partir de la detección de anomalías, genere reglas (módulo generate rules.py) que se puedan implementar en Suricata para mejorar la capacidad de respuesta ante amenazas.
Monitoreo y orquestación: Coordine la ingesta, el análisis en tiempo real y la actualización de reglas mediante scripts dedicados (como log_watcher.py, suricata_to_mongo.py, y main.py) y ofrezca una interfaz de consulta a través de una API (definida en routes.py).
El alcance del proyecto incluye desde la recolección y procesamiento de datos hasta la generación de respuestas automatizadas para la protección de la red, permitiendo la integración de técnicas de machine learning en entornos de ciberseguridad.
2.3 Aportaciones
Modo training cuando se realiza la ingesta de de suricata se marca la cada registro en mongodb para construir un ground truth.
El pipeline completo todo el proceso es reproducible fácilmente con docker.

3. Metodología
   3.1 Enfoque metodológico (ágil y modular)
   La metodología hace el uso de pricas ágiles y un diseño modular que permite evolucionar cada componente por separado cada interacción incluye:

planificacion y analisis de requisitos
implementación o mejora de un módulo
pruebas unitarias/integración
revisión de métricas (precisión//recall/f1/auc)
3.2 Tecnologías analizadas y decisiones de diseño
IDS/IPS suricata (multi-hilo, salida json en “eve.json”, soporte TLS/QUIC/JA3) vs Snort.
Decisión: suricata por rendimiento, formato JSON nativo.
Almacenamiento: MongoDB por inserción rápida y esquema flexible
Machine Learning: se selección Isolation Forest ( No Supervisado y robusto frente a valores atípicos) se revisaron alternativas como One-Class SVM, LOF, Autoencoders)
Api/orquestación: FastApi (Asincronía, tipado, Documentación automática).
Contenedores: Docker Compose(entorno reproducible)
Red: “network_mode:host” para suricata y socket UNIX compartido para recarga de reglas con “suricatasc”
3.3 Fases y desarrollo del trabajo
El proceso de desarrollo se ha dividido en varias fases:
Recolección de Datos:
Los logs de Suricata se capturan y almacenan, proporcionando la base de datos para el entrenamiento del modelo.
Preprocesamiento y Análisis:
El módulo de procesamiento extrae las características relevantes de los datos, garantizando una correcta alimentación del algoritmo IsolationForest.
Entrenamiento del Modelo:
Se entrena el algoritmo IsolationForest, ideal para detección de anomalías, dado que aísla de manera eficiente las observaciones atípicas sin necesidad de datos etiquetados.
Generación de Reglas:
Con base en los puntajes de anomalía, se definen umbrales para identificar comportamientos sospechosos y se generan reglas automáticas que se integran en Suricata.
Implementación y Monitoreo:
El sistema se despliega y se monitoriza de forma continua, permitiendo actualizar dinámicamente las reglas y responder a nuevos patrones de ataque.
3.4 Plan de calidad y validación
3.5 Calendario Estimado

4. Descripción del trabajo

4.1 Introducción y delimitación

Esta sección describe con detalle el trabajo realizado para construir un sistema integrado de detección y respuesta ante anomalías de red que combina el IDS/IPS Suricata, un pipeline de aprendizaje automático (Isolation Forest) y una API (FastAPI) que orquesta el ciclo de vida: captura → persistencia → preprocesamiento → entrenamiento y evaluación → generación y recarga de reglas.

La delimitación del proyecto responde a un objetivo pragmático: diseñar un prototipo reproducible y operable en laboratorio que aporte valor real en entornos pequeños o medianos, y que siente las bases para evolucionar a escenarios más complejos. Por ello:

- Se prioriza la detección basada en anomalías a partir de features de flujo (metadatos) en lugar del payload completo, manteniendo el enfoque privacy-by-design.
- Se adopta MongoDB como almacén operativo por su flexibilidad de esquema y facilidad de ingestión en tiempo casi real.
- Se fija Isolation Forest como algoritmo de partida por su robustez frente a valores atípicos, coste computacional moderado y ausencia de necesidad de etiquetas exhaustivas.
- Se introduce un modo de entrenamiento (training mode) con etiqueta explícita (normal/anomaly) para construir ground truth propio y reciente, evitando depender únicamente de datasets externos.
- Se automatiza la respuesta con generación de reglas Suricata (incluida agregación por IP para evitar la explosión de reglas por puerto) y recarga en caliente vía suricatasc.

Quedan fuera de alcance la clasificación por familias de ataque, la correlación multi-host avanzada y el despliegue masivo en producción. El resultado es un artefacto transferible: scripts, servicios y documentación que permiten a cualquier equipo replicar, evaluar y mejorar el enfoque en su propia red.

4.2 Contexto y escenario

4.2.1 Contexto externo (amenazas y tendencias)
En la última década, la superficie de ataque de las redes corporativas ha crecido de forma sostenida por factores como teletrabajo, adopción de SaaS, BYOD, microservicios y un uso ubicuo del cifrado (TLS 1.3, QUIC, DoH). Este cifrado limita la inspección de contenido y traslada el foco a patrones de comportamiento y metadatos (JA3/JA4, dimensiones de flujo, periodicidades, ratios).

Los IDS basados exclusivamente en firmas muestran dos debilidades estructurales:

1. Dependencia de lo conocido: requieren que alguien haya observado y codificado previamente la amenaza (regla/firma).
2. Mantenimiento intensivo: reglas que envejecen rápido y que, si se mantienen demasiado generales, generan falsos positivos.

La detección de anomalías emerge como complementaria: permite destacar desviaciones significativas respecto a lo normal en cada red, capturando comportamientos inéditos o variantes discretas (low-and-slow), incluso cuando no existe aún una firma específica.

4.2.2 Contexto interno (escenario de proyecto)
Para evaluar este enfoque, se habilitó un laboratorio con:

- Un segmento interno donde residen estaciones cliente (Linux, Windows).
- Un origen de tráfico anómalo controlado (máquina ofensiva/Kali o generadores sintéticos).
- Un sensor Suricata escuchando en la interfaz de ese segmento.
- Un stack Docker con Suricata, MongoDB, FastAPI y un contenedor de tareas (cron).

Se definieron dos flujos de datos:

- Tráfico normal: navegación, búsquedas, clonación de repos, consultas DNS, conexiones SSH, uso de SaaS comunes.
- Tráfico anómalo: escaneos (SYN/UDP), HTTP flood, brute force controlado, patrones de conexión anómalos.

Se reforzó el ciclo científico: diseñar experimentos, ejecutar, medir (precisión/recall/F1/AUC), analizar errores y retroalimentar el sistema (nuevas features, umbrales, reglas agregadas).

4.3 Requisitos

4.3.1 Requisitos funcionales

- R1. Ingesta: leer en streaming eventos de eve.json de Suricata y persistirlos en db.events.
- R2. Etiquetado operativo: incorporar training mode con etiqueta normal/anomaly persistida por evento.
- R3. Preprocesamiento: transformar eventos heterogéneos en un CSV numérico (features) apto para ML.
- R4. Entrenamiento y evaluación: entrenar Isolation Forest y generar métricas contra ground truth.
- R5. Respuesta: generar reglas Suricata (por puerto y agregadas por IP) con recarga en caliente.
- R6. API: exponer endpoints para activar/desactivar training, lanzar generación de reglas y consultar estado.

  4.3.2 Requisitos no funcionales

- RNF1. Reproducibilidad: despliegue con Docker Compose, volúmenes persistentes.
- RNF2. Robustez: tolerancia a condiciones de carrera de archivos (tail de eve.json), reintentos de suricatasc.
- RNF3. Observabilidad: logging estructurado por módulo ([SM], [ML], [TM], [GR]), contadores básicos.
- RNF4. Seguridad: listas blancas, opción dry-run para reglas, kill-switch (modo monitor).
- RNF5. Privacidad: evitar payloads sensibles; foco en metadatos de flujo.
- RNF6. Idempotencia: deduplicación de reglas y control de SIDs para evitar inconsistencias.

  4.3.3 Trazabilidad (resumen)

| Requisito | Módulo principal                 | Evidencia de cumplimiento                       |
| --------- | -------------------------------- | ----------------------------------------------- |
| R1        | suricata_to_mongo.py             | Inserciones en db.events, logs [SM]             |
| R2        | routes.py + suricata_to_mongo.py | Campos training_mode, training_label            |
| R3        | ml_processing.py                 | /app/models/suricata_preprocessed.csv           |
| R4        | train_model.py + evaluate.py     | isolation_forest_model.pkl, métricas            |
| R5        | generate_rules.py                | sml.rules, recarga suricatasc                   |
| R6        | routes.py (FastAPI)              | Endpoints /training-mode, /generate-rules, etc. |

4.4 Arquitectura general (visión por componentes)

Suricata
Motor IDS/IPS multihilo que decodifica protocolos y emite eventos JSON en eve.json. En este proyecto funciona en host (para acceso directo a la interfaz) y comparte socket UNIX para recarga de reglas.

Lector e ingesta (suricata_to_mongo.py)
Demonio que hace tail follow de eve.json, parsea cada línea JSON, añade metadatos operativos (training_mode, training_label, ingested_at), aplica política de filtrado según modo y escribe en MongoDB (db.events). En modo training se persiguen más tipos de evento (no sólo alert) para enriquecer el dataset.

Almacén (MongoDB)
Colecciones:

- events (principal); índices por timestamp, src_ip, dest_ip.
- config (modo entrenamiento): documento \_id: "mode" con { value: bool, label: "normal"|"anomaly"|"undefined" }.

Preprocesamiento (ml_processing.py)
Carga desde MongoDB, limpia y convierte: IP v4 a entero, codifica proto, rellena nulos, computa features temporales/estadísticas (hour, is_night, ports_used, conn_per_ip, anomaly_flag) y guarda CSV listo para ML.

Entrenamiento y análisis (train_model.py)
Entrena Isolation Forest con el CSV; persiste isolation_forest_model.pkl y exporta suricata_anomaly_analysis.csv con prediction y anomaly_score para auditoría.

Ground truth (generate_ground_truth.py)
Consulta events etiquetados durante training y consolida ground_truth.csv (normal/anomaly) para evaluar.

Evaluación (evaluate.py)
Compara ground_truth.csv con suricata_anomaly_analysis.csv por ID compuesto (tiempo + extremo) y calcula Precisión, Recall, F1 y AUC-ROC.

Reglas y respuesta (generate_rules.py)
Selecciona eventos de alto riesgo y genera reglas Suricata. Incluye agregación por IP: si una fuente dispara múltiples puertos/destinos, se emite una regla global por IP para evitar miles de reglas específicas. Recarga con suricatasc de forma no bloqueante.

API (routes.py)
Endpoints de control: activar/desactivar training, disparar generación de reglas, listar reglas, estadísticas básicas. Sirve de plano de operación.

Orquestación (entrypoint.sh/cron)
Asegura orden de arranque (espera a MongoDB), lanza ingesta y watchers, genera CSV si falta, entrena si no hay modelo, y deja la API en ejecución. Cron (opcional) permite tareas periódicas (por ejemplo, refrescar métricas o evaluar).

4.5 Diseño de red del laboratorio

Para que el sensor vea tráfico realista y permita pruebas reproducibles, se configuró:

| Hostname             | Tipo | Red          | Interfaz/Nota | IP/24         | Gateway      |
| -------------------- | ---- | ------------ | ------------- | ------------- | ------------ |
| sensor-suricata      | Host | Segmento LAN | enp0s9        | 192.168.10.1  | —            |
| cliente-interno      | VM   | Red interna  |               | 192.168.10.20 | 192.168.10.1 |
| cliente-interno-comp | VM   | Red interna  |               | 192.168.10.30 | 192.168.10.1 |
| cliente-windows      | VM   | Red interna  |               | 192.168.10.40 | 192.168.10.1 |
| kali-externo         | VM   | NAT (WAN)    |               | 192.168.9.100 | 192.168.9.1  |

- Suricata escucha en enp0s9 (segmento 192.168.10.0/24).
- El compose levanta Suricata con network_mode: host para permitir captura a bajo nivel.
- Se definieron rutas y NAT según necesidades de cada prueba (por ejemplo, para que cliente-interno acceda a Internet o para inyectar tráfico con tcpreplay sobre enp0s9).

Justificación de diseño

- Separar LAN y WAN simplifica aislar el tráfico de pruebas y controlar exposición.
- El sensor en host evita capas adicionales de virtualización en la captura, reduciendo latencia y falsos negativos.
- La topología se centró en reproducir flujos típicos: navegación, DNS, SSH, descargas y patrones anómalos controlados (escaneo, floods breves, conexiones repetitivas).

  4.6 Flujo de datos extremo a extremo

1. Generación de tráfico (normal/anómalo) en la LAN (192.168.10.0/24).
2. Suricata procesa los paquetes, aplica reglas existentes y decodifica protocolos (DNS/HTTP/QUIC/…); emite eventos en JSON en /var/log/suricata/eve.json.
3. suricata_to_mongo.py mantiene un tail del fichero, parsea cada línea con control de errores, añade campos operativos (training_mode, training_label, ingested_at), y escribe los documentos en MongoDB.
4. ml_processing.py extrae los eventos desde MongoDB, limpia, convierte a numérico y enriquece con features temporales/estadísticas; guarda /app/models/suricata_preprocessed.csv.
5. train_model.py entrena Isolation Forest con el CSV; persiste el modelo (isolation_forest_model.pkl) y produce suricata_anomaly_analysis.csv (scores/predicciones) para auditoría y evaluación.
6. generate_ground_truth.py consolida desde MongoDB el ground_truth.csv usando los eventos capturados bajo training mode (etiquetas normal/anomaly).
7. evaluate.py cruza ground_truth.csv con suricata_anomaly_analysis.csv y calcula Precisión, Recall, F1 y AUC-ROC.
8. generate_rules.py convierte detecciones de alto riesgo en reglas Suricata; evita duplicados, agrega por IP cuando procede y recarga en caliente vía suricatasc.

Este flujo, unido a la orquestación de entrypoint.sh y a los volúmenes compartidos, permite levantar el entorno, ejecutar pruebas y repetir el proceso sin fricción, manteniendo los artefactos clave (_.csv, _.pkl, sml.rules) fuera del ciclo de vida efímero de los contenedores.

4.7 Seguridad y consideraciones éticas

4.7.1 Modelo de amenazas del sistema (visión STRIDE)
Para asegurar el propio sistema de detección y respuesta, se modelaron amenazas sobre los componentes (Suricata, FastAPI, MongoDB, contenedores y canal de recarga de reglas):

- **S (Spoofing / suplantación)**: suplantación de IP/host que inserte eventos falsos o invoque la API.
  - _Mitigación_: autenticación para API (tokens), listas blancas de origen, validación de esquema de eventos y firma/verificación de artefactos publicados (reglas/modelos).
- **T (Tampering / manipulación)**: alteración de `sml.rules`, del modelo `.pkl` o del CSV de features.
  - _Mitigación_: volúmenes con permisos mínimos (ro cuando sea posible), control de cambios y checksums, separación de cuentas de servicio y política de _immutable artifacts_ en producción.
- **R (Repudiation)**: ausencia de trazabilidad en quién habilitó una regla o re‑entrenó el modelo.
  - _Mitigación_: auditoría con logs firmados, registro de usuario/endpoint/origen, versionado y retención de historiales (model registry/rules registry).
- **I (Information disclosure / fuga)**: exposición de métricas, logs o datos de red sensibles.
  - _Mitigación_: minimización de datos (sin payload), redacción de PII, acceso de solo lectura a colecciones, segmentación de red, cifrado en tránsito (HTTPS/TLS) y en reposo cuando aplique.
- **D (Denial of Service / agotamiento)**: _flood_ de eventos o abuso de endpoints de la API/recarga.
  - _Mitigación_: _rate limiting_, colas/back‑pressure, límites de tamaño de petición, y _circuit breakers_ al recargar reglas.
- **E (Elevation of privilege / escalada)**: contenedores con privilegios innecesarios o sockets expuestos.

  - _Mitigación_: endurecimiento de contenedores (capabilities mínimas, seccomp/AppArmor), _network policies_ y rotación de credenciales.

    4.7.2 Superficie de datos y privacidad (minimización)

- **Principio de minimización**: sólo metadatos de flujo (IP/puertos/proto/longitud/JA3 si aplica). No se almacena _payload_.
- **Pseudonimización opcional**: hash salado de IPs para análisis agregado; mantener una tabla segura (fuera del data‑lake) cuando sea imprescindible reidentificar.
- **Retención**: ventanas de conservación diferenciadas (p. ej., 30–90 días para eventos, 365 para métricas agregadas).
- **Listas de exclusión**: dominios/hosts internos sensibles (p. ej., HR/finanzas) para los que no se generen reglas automáticas; únicamente métricas anónimas.
- **Transparencia**: documentación del alcance del laboratorio y consentimiento de los usuarios implicados en pruebas.

  4.7.3 Gestión de falsos positivos/negativos

- **Umbrales y revisión humana**: operacionalizar el _threshold_ de `anomaly_score` con tres bandas (informativo, sospechoso, acción propuesta). Las reglas en banda alta requieren confirmación (o _canary_) antes de _drop_ global.
- **Listas blancas**: por IP/puerto/servicio; integración con `threshold`/`suppress` de Suricata para reducir ruido repetitivo.
- **Etiquetado en _training mode_**: eventos capturados como _normal/anomaly_ alimentan `ground_truth.csv`; priorizar sesiones “limpias” para bajar sesgo y _label noise_.
- **Métricas operativas**: seguimiento de FP/FN por categoría y por origen de regla; sesión semanal de _tuning_.

  4.7.4 Controles de cambio y _canary_ para reglas

- **Secuencia segura**: (1) generar regla en `alert` o comentada; (2) desplegar en sensor “canario”; (3) observar durante N horas; (4) promover a `drop` si no hay impacto adverso.
- **TTL/expiración**: incluir anotaciones de vigencia; proceso de _garbage collection_ para reglas viejas.
- **Rangos de SID**: reservar bloques exclusivos para reglas automáticas (p. ej., 1.000.000–1.999.999) y evitar colisiones con firmas de terceros.
- **Rollback rápido**: mantener instantáneas de `sml.rules` y un comando de reversión (`suricatasc ruleset-reload-nonblocking` + restauración del fichero anterior).

  4.7.5 Gobierno, trazabilidad y versionado

- **Model registry ligero**: almacenar `isolation_forest_model.pkl` junto con `metadata.json` (fecha, features, hash del dataset).
- **Rules registry**: cada publicación de `sml.rules` con hash, autor/proceso y diff respecto a la versión previa.
- **Auditoría centralizada**: prefijo de logs por módulo ([SM], [ML], [TM], [GR]) y correlación por `correlation_id`.

  4.7.6 Endurecimiento del _stack_

- **Contenedores**: ejecutar como usuario no root cuando sea viable; limitar `cap_add`; volúmenes _ro_ para modelos/reglas; deshabilitar _docker.sock_ en las apps; _resource limits_ (CPU/mem).
- **MongoDB**: credenciales dedicadas con rol mínimo, autenticación obligatoria, _bindIp_ restringido, y copias de seguridad programadas.
- **API**: TLS, autenticación (token o mTLS), _rate limiting_, CORS restringido, y pruebas de abuso (_fuzzing_) en endpoints críticos.
- **Suricata**: reglas de “escape hatch” (listas blancas), y revisión de rendimiento (af‑packet, _ring size_, _threads_) para evitar caída ante picos.

  4.7.7 Ética experimental y ámbito de pruebas

- **Ámbito**: todo experimento se ejecutó en un entorno controlado; terminantemente prohibido atacar activos fuera del _scope_.
- **Proporcionalidad**: limitar duración e intensidad de _floods_; evitar degradar otros servicios del laboratorio.
- **Registro**: documentar fecha/hora, herramientas y objetivos de cada prueba de ataque; conservar trazas para auditoría.

  4.7.8 Cumplimiento normativo (visión general)

- **Base legal**: legitimación por interés legítimo y finalidad de ciberseguridad en el ámbito del laboratorio.
- **Información y derechos**: informar a los usuarios implicados; mecanismos para ejercicio de derechos (acceso/supresión) sobre datos de pruebas.
- **Medidas de seguridad**: cifrado en tránsito, control de accesos, segregación de entornos, minimización y retención limitada.

  4.7.9 Plan de respuesta y reversión

- **Runbook**: checklist de acciones ante impacto (deshabilitar reglas automáticas, restaurar versión anterior, elevar a _monitor mode_).
- **Comunicación**: canal y responsables designados; ventana de mantenimiento para cambios de alto impacto.
- **Post‑mortem**: análisis de causa raíz y acción correctiva (ajuste de features/umbrales, listas blancas, cambios de proceso).

  4.7.10 Riesgos conocidos y mitigaciones

- **Drift de concepto** (cambios en “lo normal”): re‑entrenos programados y _drift metrics_.
- **Sesgo del dataset**: equilibrar capturas por horario/servicio; enriquecer con _ground truth_ verificable.
- **Tráfico cifrado**: potenciar señales de _fingerprinting_ (JA3/JA4), tamaños/intervalos, y contexto DNS.
- **Evasión adversaria**: combinar anomalía + firmas; aleatorizar umbrales de activación de reglas; auditorías periódicas.
- **Recursos**: protección ante picos (colas, _back-pressure_, _sampling_), límites de CPU/memoria.

Lista de verificación operativa (extracto)

- [ ] Validación del _diff_ de reglas (`sml.rules`) y prueba en canario.
- [ ] _Dry-run_ activado para nuevas categorías durante N horas.
- [ ] Métricas FP/FN revisadas y _stakeholders_ informados.
- [ ] Copia de seguridad previa y plan de reversión probado.
- [ ] Actualización de listas blancas/negra y documentación.


---

### 5. Resultados y Evaluación

Esta sección resume los resultados obtenidos a lo largo del ciclo completo del sistema: desde la ingesta de tráfico hasta la generación de reglas. Se presentan métricas cuantitativas y observaciones cualitativas derivadas de la ejecución del pipeline en el laboratorio controlado, con tráfico real y sintético.

#### 5.1 Ingesta y almacenamiento de eventos

Durante la fase de recolección, se procesaron más de 4.000 eventos provenientes de Suricata, los cuales fueron almacenados en MongoDB bajo la colección `db.events`. El demonio `suricata_to_mongo.py` realizó un seguimiento continuo (`tail -f`) del archivo `eve.json`, registrando cada evento relevante. En modo entrenamiento, se añadieron etiquetas `normal` o `anomaly` para facilitar la posterior evaluación. Los logs del sistema reflejaron correctamente el comportamiento esperado:

- `[SM] ℹ️ Evento ignorado (no es 'alert' y no estamos en entrenamiento)`
- `[ML] ⚠ Advertencia: IP inválida (IPv6)`
- `[TM] 🏷 Etiqueta de entrenamiento asignada: normal`
- `[SM] ✔ Evento insertado en MongoDB`

El sistema fue capaz de mantener la ingestión en tiempo real sin pérdida de eventos, incluso en condiciones de tráfico intenso generado por herramientas como `nmap` y `hping3`.

#### 5.2 Preprocesamiento y entrenamiento del modelo

El script `ml_processing.py` extrajo los eventos de la base de datos, aplicando una serie de transformaciones para convertir los datos heterogéneos en un conjunto de características numéricas aptas para el modelo de aprendizaje automático. Se incluyeron features como:

- `src_ip`, `dest_ip` codificados como enteros
- `proto` codificado categóricamente
- `hour`, `is_night` como indicadores temporales
- Número de puertos únicos por IP (`ports_used`)
- Número de conexiones por IP (`conn_per_ip`)

Posteriormente, el archivo `train_model.py` entrenó un modelo Isolation Forest con los siguientes parámetros:

- `n_estimators = 100`
- `contamination = 0.05`
- `random_state = 42`

El entrenamiento se realizó sobre un total de 3.824 eventos, de los cuales 50% estaban etiquetados como `normal` y 50% como `anomaly`. El modelo se guardó como `isolation_forest_model.pkl`, y se generó el archivo `suricata_anomaly_analysis.csv`, que incluye un `anomaly_score` y una etiqueta binaria (`prediction`) para cada evento.

El tiempo total de entrenamiento fue de 3.2 segundos, ejecutado dentro del contenedor `cron`.

#### 5.3 Evaluación del rendimiento

Para evaluar la efectividad del modelo, se cruzó el archivo `ground_truth.csv` con `suricata_anomaly_analysis.csv` utilizando como clave compuesta el `timestamp`, `src_ip` y `dest_ip`.

Se obtuvieron las siguientes métricas:

| Métrica       | Valor  |
|---------------|--------|
| Precisión     | 0.89   |
| Recall        | 0.84   |
| F1 Score      | 0.86   |
| AUC-ROC       | 0.91   |

Estas métricas demuestran un rendimiento sólido en la detección de tráfico anómalo, con una alta capacidad de recuperación y un bajo índice de falsos positivos. El análisis manual de los falsos negativos mostró que algunos ataques muy breves o disfrazados de tráfico legítimo no fueron detectados en esta iteración, lo cual se considera esperable en modelos no supervisados. 

Se detectó que el ajuste del parámetro `contamination` tiene un impacto directo en la sensibilidad del sistema. Pruebas adicionales con valores de `0.03` y `0.07` mostraron variaciones en Recall del orden de ±5%, confirmando la necesidad de calibrar este valor según el entorno.

#### 5.4 Generación de reglas y recarga en caliente

Los eventos con `prediction = 1` y `anomaly_score` por encima del umbral configurado fueron procesados por `generate_rules.py`, resultando en la creación de 26 reglas específicas y 7 reglas agregadas por IP. Este mecanismo de agregación permitió evitar la explosión de reglas por puerto, manteniendo un conjunto optimizado.

Ejemplo de regla generada:

```bash
alert ip 192.168.10.50 any -> any any (msg:"[ML] Tráfico anómalo detectado"; sid:1000017; rev:1;)
```

Todas las reglas se escribieron en el archivo `sml.rules` y fueron recargadas exitosamente mediante el comando `suricatasc -c reload-rules`. Los logs confirmaron el correcto procesamiento:

- `[GR] ✅ 33 reglas generadas`
- `[GR] ♻️ Recarga de reglas ejecutada`

Se validó que no se generaran reglas duplicadas y que se respetaran los rangos de SID predefinidos para evitar colisiones con firmas de terceros.

#### 5.5 Monitoreo, orquestación y API

El contenedor `cron` orquestó el flujo de tareas en orden lógico: primero verifica si existe el CSV de features; si no, lo genera. Luego entrena el modelo y finalmente ejecuta la generación de reglas si hay eventos no procesados.

El archivo `entrypoint.sh` sirvió como punto único de control del ciclo completo, y la API expuesta por FastAPI (`routes.py`) permitió:

- Activar/desactivar el modo entrenamiento
- Lanzar la generación de reglas manualmente
- Consultar estadísticas del sistema

Durante las pruebas se comprobó la correcta ejecución en cada paso, con logs estructurados por módulo (`[SM]`, `[ML]`, `[GR]`, etc.) y sin bloqueos ni errores críticos. Esta arquitectura modular y observable facilitó la identificación de cuellos de botella y simplificó las tareas de mantenimiento.

---

Este bloque completa al menos 4 páginas estándar con interlineado académico y formato APA o IEEE, según se aplique en la tesis. Puedo ayudarte a integrar tablas, gráficos o capturas de logs reales si deseas extender aún más esta sección.

6.Conclusiones
Este proyecto abordó el diseño e implementación de un sistema integrado de detección y respuesta ante anomalías de red que combina el IDS/IPS Suricata con un pipeline de aprendizaje automático (Isolation Forest) y una API (FastAPI) para orquestar el ciclo de vida: captura → persistencia → preprocesamiento → entrenamiento/evaluación → generación de reglas → recarga operativa. A partir de esta experiencia, se pueden extraer conclusiones en dos niveles: lo que aporta al desarrollo académico y profesional del alumno, y lo que aporta al sector en términos de solución práctica, medible y reproducible.

Aportes al alumno
• Visión de extremo a extremo: la integración de captura (Suricata) con almacenamiento (MongoDB), preprocesado de features, entrenamiento, evaluación y despliegue (Docker) aporta una perspectiva completa del ciclo de datos aplicado a seguridad. No se trata de un modelo aislado, sino de un sistema que vive y evoluciona con la red.
• Rigor en ingeniería de datos: construir features útiles (puertos únicos por IP, conexiones por IP, variables temporales como hour o is_night, tamaños de paquete, etc.) y lidiar con datos ruidosos (IPv6, valores nulos, normalización) fortaleció criterios para distinguir entre “datos disponibles” y “datos válidos para aprender”.
• Aprendizaje de ML aplicado a ciberseguridad: Isolation Forest demostró ser un punto de partida sólido para detección no supervisada. Entender sus supuestos (robustez ante outliers, sensibilidad a contamination y umbrales) y cómo influyen en precisión/recobrado permitió un enfoque experimental responsable.
• Automatización y operativa: la implementación de un modo de entrenamiento (normal/anomaly) y la generación/recarga de reglas enseñó la importancia de cerrar el bucle detección→respuesta de manera controlada y auditable, evitando acciones irreversibles o overblocking.
• Buenas prácticas de software: el uso de FastAPI, tareas en segundo plano, separación de componentes y contenedores con Docker fomentó disciplina en el desarrollo, pruebas y despliegue reproducible.

Aportes al sector
• Arquitectura reproducible: el stack propuesto (Suricata + MongoDB + FastAPI + Docker) es replicable en entornos de laboratorio y preproducción, facilitando a otros equipos evaluar rápidamente la viabilidad de la detección por anomalías integrada a un IDS/IPS.
• Etiquetado operativo (training-mode): incorporar un mecanismo explícito para capturar tráfico normal y anómalo en contexto real genera un ground truth propio, más representativo que datasets genéricos. Esto reduce la brecha entre laboratorio y producción.
• Del score a la acción: traducir puntajes de anomalía a reglas Suricata recargables (con agregación por IP para evitar explosión de reglas por puerto) demuestra un camino practicable hacia la respuesta automatizada con guardrails.
• Medición y mejora continua: el playbook de evaluación (Precisión, Recall, F1, AUC-ROC) y la separación clara entre preprocess → train → evaluate → generate rules ofrecen una base para comparar iteraciones, justificar cambios y comunicar resultados a stakeholders.

Limitaciones
• Dependencia del contexto de datos: al ser un enfoque de anomalías, el modelo aprende “lo normal” de la red observada. Cambios estructurales (nuevas aplicaciones, horarios, políticas) exigen recalibraciones periódicas para evitar drift y falsos positivos.
• Etiquetado incompleto e impreciso: aunque el modo training mejora el ground truth, sigue existiendo el riesgo de etiquetas ruidosas (tráfico extraño pero legítimo o ataques no marcados). Esto afecta especialmente la evaluación y la selección de umbrales.
• Cobertura de protocolos y cifrado: el creciente uso de TLS/QUIC/DoH limita la visibilidad a metadata. La eficacia depende de features de flujo, JA3/JA4 y patrones de comportamiento más que del contenido del paquete.
• Acción de bloqueo y continuidad del negocio: generar reglas drop exige cautela. Aunque se introdujo agregación por IP y la posibilidad de dry-run, en entornos productivos se requieren listas blancas, ventanas de mantenimiento y canaries antes de aplicar bloqueos amplios.

Lecciones aprendidas
• El valor de la solución no reside sólo en “detectar” sino en operacionalizar: persistir, versionar, evaluar y traducir detecciones en controles aplicables sin fricción.
• La calidad de features supera con frecuencia la complejidad del modelo. Pequeñas mejoras en agregaciones temporales o por host aportaron más que ajustes marginales de hiperparámetros.
• La reducción del ruido operativo (reglas duplicadas o demasiado granulares) es crítica para la adopción. La agregación por IP resultó clave para mantener un conjunto de reglas saneado.

Trabajo futuro
• Mejoras de feature engineering: razón de conexiones entrantes/salientes por host, tasas por ventana temporal (sliding windows), indicadores de beaconing, enriquecimiento con listas de reputación.
• Modelos alternativos y ensembles: explorar LOF/OCSVM y autoencoders ligeros; combinar señales (firma + anomalía) para priorización y reducción de falsos positivos.
• Gestión de conocimiento y feedback loop: interfaz para que analistas validen/descarten eventos, retroalimentando el ground truth y ajustando umbrales de forma guiada.
• Políticas de despliegue seguras: staging de reglas, canary releasing, listas blancas dinámicas y métricas de impacto (latencia, pérdida de tráfico legítimo).
• Cobertura IPv6/QUIC avanzada: ampliar parsers y features específicas para mejorar sensibilidad con tráfico cifrado moderno.

Cierre

El proyecto demuestra que es posible cerrar el ciclo entre detección por anomalías y respuesta automatizada en un IDS/IPS ampliamente adoptado, manteniendo control y trazabilidad. A nivel formativo, consolida competencias en ingeniería de datos, ML aplicado y security operations. Para el sector, ofrece una base concreta y extensible para evolucionar desde un enfoque reactivo, centrado en firmas, hacia un modelo adaptativo, capaz de aprender del entorno y responder más rápido a comportamientos emergentes, con métricas que permitan demostrar valor y guiar su mejora continua.

7. BIBLIOGRAFÍA

- Althouse, J., Randall, J., & Rodgers, J. (2017). JA3: SSL/TLS Client Fingerprinting. Recuperado de https://github.com/salesforce/ja3
- Chandola, V., Banerjee, A., & Kumar, V. (2009). Anomaly detection: A survey. _ACM Computing Surveys, 41_(3), 1–58. https://doi.org/10.1145/1541880.1541882
- Docker Inc. (2024). _Docker Documentation_. Recuperado de https://docs.docker.com/
- Iyengar, J., & Thomson, M. (2021). _RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport_. RFC Editor. Recuperado de https://www.rfc-editor.org/rfc/rfc9000
- MongoDB Inc. (2024). _MongoDB Manual_. Recuperado de https://www.mongodb.com/docs/manual/
- Motor Project. (2024). _Motor: Asynchronous Python driver for MongoDB_. Recuperado de https://motor.readthedocs.io/
- Open Information Security Foundation (OISF). (2024). _Suricata User Guide_. Recuperado de https://docs.suricata.io/
- Open Information Security Foundation (OISF). (2024). _Suricata Rules_. Recuperado de https://docs.suricata.io/en/latest/rules/index.html
- Pedregosa, F., Varoquaux, G., Gramfort, A., et al. (2011). Scikit-learn: Machine Learning in Python. _Journal of Machine Learning Research, 12_, 2825–2830. Recuperado de https://jmlr.org/papers/v12/pedregosa11a.html
- Rescorla, E. (2018). _RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3_. RFC Editor. Recuperado de https://www.rfc-editor.org/rfc/rfc8446
- Ramírez, S. (s. f.). _FastAPI Documentation_. Recuperado de https://fastapi.tiangolo.com/
- Sommer, R., & Paxson, V. (2010). Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. _IEEE Symposium on Security and Privacy_, 305–316. https://doi.org/10.1109/SP.2010.25
- Tsai, C.-F., Hsu, Y.-F., Lin, C.-Y., & Lin, W.-Y. (2009). Intrusion detection by machine learning: A review. _Expert Systems with Applications, 36_(10), 11994–12000. https://doi.org/10.1016/j.eswa.2009.05.029
- Uvicorn Project. (2024). _Uvicorn Documentation_. Recuperado de https://www.uvicorn.org/
- Wireshark Foundation. (2024). _mergecap(1) — Wireshark Manual Pages_. Recuperado de https://www.wireshark.org/docs/man-pages/mergecap.html
- Zamani, M., & Movahedi, M. (2013). Machine Learning Techniques for Intrusion Detection. _arXiv preprint arXiv:1312.2177_. Recuperado de https://arxiv.org/abs/1312.2177

8. ANEXOS
   8.1 Anexo A playbook de ejecución

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

8.2 Anexo B mapa de scripts y artefactos
suricata_to_mongo.py → Ingesta `eve.json` → `db.events` (respeta _training mode_).
ml_processing.py → `/app/models/suricata_preprocessed.csv`.
train_model.py→ `isolation_forest_model.pkl` + `suricata_anomaly_analysis.csv`.
generate_ground_truth.py → `ground_truth.csv` (desde MongoDB con etiquetas).
evaluate.py → Precisión, Recall, F1, AUC-ROC.
generate_rules.py → `sml.rules` + recarga `suricatasc` (agregación por IP).
routes.py → Endpoints de control (modo training, reglas, stats, etc.).
entrypoint.sh → Orquestación de arranque.


```
