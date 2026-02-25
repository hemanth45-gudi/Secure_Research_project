import pytest
import os
import mongomock
from app import create_app
from core.db import set_db_client

@pytest.fixture(scope='session')
def app():
    """Create and configure a new app instance for each test session."""
    import mongomock
    from core.db import set_db_client
    
    # Use mongomock for testing to avoid needing a real MongoDB
    # MUST be set before create_app so init_db finds it
    mock_client = mongomock.MongoClient()
    set_db_client(mock_client)

    os.environ['FLASK_ENV'] = 'testing'
    app = create_app('testing')
    
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
def clean_db(app):
    """Cleans the mock database before each test."""
    from core.db import get_db
    db = get_db()
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})
