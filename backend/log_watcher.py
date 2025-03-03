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
            print("Nuevo evento detectado en Suricata. Ejecutando preprocesamiento...")

            # Ejecutar el preprocesamiento de manera segura en el event loop
            self.loop.run_in_executor(self.executor, lambda: asyncio.run(preprocess_data()))

def start_watcher(loop):
    event_handler = LogHandler(loop)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(LOG_PATH), recursive=False)

    print(f"🔍 Monitoreando cambios en {LOG_PATH}...")
    
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
