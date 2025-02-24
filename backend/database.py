from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://user:password@database:27017")

client = AsyncIOMotorClient(MONGO_URI)
db = client.suricata_db
