from motor.motor_asyncio import AsyncIOMotorClient
import os

# Configuración de la conexión a MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://user:password@mongodb:27017")  # Usa 'mongodb' en lugar de 'database'

# Crear cliente de MongoDB
client = AsyncIOMotorClient(MONGO_URI)
db = client["suricata"]  # Base de datos "suricata"

async def init_db():
    """Verifica y crea la colección 'events' si no existe."""
    collections = await db.list_collection_names()
    if "events" not in collections:
        await db.create_collection("events")
        print("✅ Colección 'events' creada.")
    else:
        print("⚡ La colección 'events' ya existe.")

