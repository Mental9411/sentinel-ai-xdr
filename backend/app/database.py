"""Legacy module — database is MongoDB. See backend.app.mongodb."""
from backend.app.mongodb import close_mongodb, connect_mongodb, ping_mongodb

__all__ = ["connect_mongodb", "close_mongodb", "ping_mongodb"]
