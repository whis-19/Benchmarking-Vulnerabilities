import os
    from flask import Flask

    app = Flask(__name__)
    app.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'your_default_secret_key'  # Use a default for development only

