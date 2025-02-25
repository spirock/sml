from fastapi import FastAPI
from routes import router  # Asegúrate de que routes.py existe
import asyncio
from db_connection import db, init_db

app = FastAPI(title="API de Seguridad con Suricata y FastAPI")

app.include_router(router)

@app.on_event("startup")
async def startup_event():
    """Se asegura de que la base de datos está lista al iniciar FastAPI."""
    await init_db()

    
@app.get("/")
async def root():
    return {"message": "API funcionando correctamente 🚀"}
