import os
    from flask import Flask

    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY")  # Get from environment variable
    app.config['DATABASE_URL'] = os.environ.get("DATABASE_URL") # Get database URL from environment variable

    # Example usage:
    if not app.secret_key:
        print("Warning: FLASK_SECRET_KEY not set.  Using a weak default for development only!")
        app.secret_key = "development_secret" # NEVER DO THIS IN PRODUCTION

