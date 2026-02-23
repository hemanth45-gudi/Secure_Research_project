"""
core/db.py   MongoDB Connection Manager
=========================================
Provides a module-level singleton connection pool.
Call init_db(app) once during app creation, then
use get_collection('name') anywhere.
"""

import logging
from pymongo import MongoClient

logger = logging.getLogger(__name__)

_client: MongoClient | None = None
_db = None


def init_db(app):
    """Initialise the MongoDB connection from app config. Call from create_app()."""
    global _client, _db
    try:
        if _client is None: # Don't overwrite if already set (e.g. in tests)
            _client = MongoClient(app.config['MONGO_URI'], serverSelectionTimeoutMS=5000)
            _db = _client[app.config['MONGO_DB']]
        
        # Ping to confirm connection (skip for mongomock)
        if hasattr(_client, 'admin'):
            _client.admin.command('ping')
            
            # -- Scalability: Database Indexes ---------------------
            def safe_index(col, *args, **kwargs):
                try:
                    col.create_index(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Could not create index on {col.name} {args}: {e}")

            safe_index(_db.users, 'username', unique=True)
            safe_index(_db.users, 'email', unique=True)
            safe_index(_db.datasets, 'uploader')
            safe_index(_db.datasets, 'created_at')
            safe_index(_db.logs, 'timestamp')
            safe_index(_db.logs, 'user')
            
        print(f"\n[OK MONGODB] Connected & Indexed -> {app.config['MONGO_DB']}\n", flush=True)
    except Exception as e:
        print(f"\n[ERROR MONGODB] Connection failed: {e}\n", flush=True)
        # We still raise if the connection itself fails, but index failures are warnings
        raise
    return _db

def set_db_client(client):
    """Set the database client manually (useful for testing)."""
    global _client, _db
    _client = client
    _db = client['test_db']


def get_db():
    """Return the active database instance."""
    if _db is None:
        raise RuntimeError("Database not initialised. Call init_db(app) first.")
    return _db


def get_collection(name: str):
    """Shorthand: get_collection('users') -> db['users']"""
    return get_db()[name]


# Named collection shortcuts used throughout the project
def users():           return get_collection('users')
def datasets():        return get_collection('datasets')
def logs():            return get_collection('logs')
def refresh_tokens():  return get_collection('refresh_tokens')
def login_attempts():  return get_collection('login_attempts')
