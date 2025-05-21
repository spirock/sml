"""
log_watcher.py

📌 Propósito:
    Este módulo monitorea en tiempo real los cambios en el archivo de logs de Suricata (eve.json).
    Cuando se detecta una modificación, se dispara automáticamente el preprocesamiento de los nuevos datos.

⚙️ Funcionalidad principal:
    - Usa watchdog para observar el archivo eve.json.
    - Al detectar cambios, lanza el proceso de preprocesamiento (ml_processing.main).
    - Esto asegura que los datos estén siempre listos para su análisis o entrenamiento.

🔁 Flujo:
    1. Suricata escribe eventos en eve.json.
    2. watchdog detecta el cambio.
    3. Se ejecuta el script de ml_processing.
    4. Se genera o actualiza suricata_preprocessed.csv con los datos recientes.

🧩 Dependencias:
    - watchdog
    - asyncio
    - ml_processing.py (debe tener una función main compatible con ejecución async)
"""
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from ml_processing import main as preprocess_data

LOG_PATH = "/var/log/suricata/eve.json"

class LogHandler(FileSystemEventHandler):
    def __init__(self, loop):
        self.loop = loop
        self.executor = ThreadPoolExecutor(max_workers=1)  # Ejecutar una tarea a la vez

    def on_modified(self, event):
        if event.src_path == LOG_PATH:
            print("[LogW]Nuevo evento detectado en Suricata. Ejecutando preprocesamiento...")

            # Ejecutar el preprocesamiento de manera segura en el event loop
            self.loop.run_in_executor(self.executor, lambda: asyncio.run(preprocess_data()))

def start_watcher(loop):
    event_handler = LogHandler(loop)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(LOG_PATH), recursive=False)

    print(f"[LogW] 🔍 Monitoreando cambios en {LOG_PATH}...")
    
    observer.start()
    
    try:
        while True:
            time.sleep(5)  # Evita que el proceso termine
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()

if __name__ == "__main__":
    loop = asyncio.new_event_loop()  # Crear un event loop separado
    asyncio.set_event_loop(loop)

    start_watcher(loop)  # Iniciar el monitoreo con el loop correcto
