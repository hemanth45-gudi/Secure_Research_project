import os
from app import create_app

# Use the FLASK_ENV environment variable, default to 'production'
env = os.environ.get('FLASK_ENV', 'production')
app = create_app(env)

if __name__ == '__main__':
    # For local development debugging
    app.run(host='0.0.0.0', port=5000)
