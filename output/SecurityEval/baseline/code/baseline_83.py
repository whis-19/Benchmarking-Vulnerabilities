from flask import Flask, make_response, request
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

app = Flask("dummy")

# Load environment variables from .env file (if it exists)
load_dotenv()

# Default database URI (override with environment variable)
DEFAULT_DATABASE_URI = 'sqlite:///:memory:'  # In-memory database for testing

def configure_app(app):
    """
    Configures the Flask app with database settings.  Retrieves the database URI
    from the environment variables or uses a default.  Also initializes the
    SQLAlchemy engine and session.

    Args:
        app: The Flask application instance.
    """

    # Get database URI from environment variable, or use the default
    database_uri = os.environ.get("DATABASE_URI", DEFAULT_DATABASE_URI)

    # Ensure the database URI is properly formatted and safe.  Consider using a
    # dedicated configuration management system for more complex setups.
    if not isinstance(database_uri, str):
        raise TypeError("DATABASE_URI must be a string.")

    # Set the SQLAlchemy database URI in the app configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri

    # Initialize SQLAlchemy engine and session
    try:
        engine = create_engine(database_uri)
        app.engine = engine  # Store the engine in the app context

        # Create a session factory
        Session = sessionmaker(bind=engine)
        app.Session = Session  # Store the session factory in the app context

        # Create the database tables (if they don't exist)
        Base = declarative_base()  # Define a base class for declarative models
        Base.metadata.create_all(engine)

    except Exception as e:
        print(f"Error connecting to the database: {e}")
        raise  # Re-raise the exception to prevent the app from starting with a broken database connection


# Example usage (assuming you have a database URI in your environment)
# configure_app(app)

# Example route (demonstrates using the database session)
# (Requires SQLAlchemy models to be defined)
"""
from sqlalchemy import Column, Integer, String

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"

@app.route("/users", methods=["POST"])
def create_user():
    session = app.Session()
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")

        if not username or not email:
            return make_response({"error": "Username and email are required"}, 400)

        new_user = User(username=username, email=email)
        session.add(new_user)
        session.commit()
        return make_response({"message": "User created successfully"}, 201)
    except Exception as e:
        session.rollback()
        print(f"Error creating user: {e}")
        return make_response({"error": "Failed to create user"}, 500)
    finally:
        session.close()
"""

if __name__ == '__main__':
    # Example usage:
    configure_app(app)  # Configure the app before running it

    # Run the Flask app (for development purposes only)
    # In production, use a proper WSGI server (e.g., Gunicorn, uWSGI)
    app.run(debug=True)

