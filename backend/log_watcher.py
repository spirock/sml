from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import asyncio
import os

# Importar el script de preprocesamiento
from ml_processing import main as preprocess_data

LOG_PATH = "/var/log/suricata/eve.json"  # Ruta donde Suricata guarda sus logs

class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == LOG_PATH:
            print("Nuevo evento detectado en Suricata. Ejecutando preprocesamiento...")
            asyncio.run(preprocess_data())

if __name__ == "__main__":
    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(LOG_PATH), recursive=False)
    
    print(f"Monitoreando cambios en {LOG_PATH}...")
    
    observer.start()
    
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()
    