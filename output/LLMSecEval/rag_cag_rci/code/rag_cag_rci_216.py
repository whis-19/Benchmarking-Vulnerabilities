import os

    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///image_database.db")
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

