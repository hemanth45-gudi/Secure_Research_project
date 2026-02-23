import pytest
import os
import mongomock
from app import create_app
from core.db import set_db_client

@pytest.fixture(scope='session')
def app():
    """Create and configure a new app instance for each test session."""
    os.environ['FLASK_ENV'] = 'testing'
    app = create_app('testing')
    
    # Use mongomock for testing to avoid needing a real MongoDB
    mock_client = mongomock.MongoClient()
    set_db_client(mock_client)
    
    yield app

@pytest.fixture(scope='function')
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture(scope='function')
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()

@pytest.fixture(autouse=True)
def clean_db():
    """Cleans the mock database before each test."""
    from core.db import get_db
    db = get_db()
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})
