from fastapi import FastAPI
from routes import router  # Asegúrate de que routes.py existe

app = FastAPI(title="API de Seguridad con Suricata y FastAPI")

app.include_router(router)

@app.get("/")
async def root():
    return {"message": "API funcionando correctamente 🚀"}
