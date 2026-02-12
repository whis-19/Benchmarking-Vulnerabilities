import os
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3  # Consider using a more robust database like PostgreSQL with SQLAlchemy for production
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps

app = Flask(__name__)

# Securely generate a secret key for session management
app.secret_key = secrets.token_hex(24)  # Generate a random 24-byte hex string

# Database Configuration (Use environment variables for sensitive data)
DATABASE = os.environ.get('DATABASE_URL', 'database.db')  # Default to 'database.db' if not set

# Function to connect to the database (using context manager for safety)
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

# Initialize the database (create tables if they don't exist)
def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:  # schema.sql should contain your table creation SQL
            db.cursor().executescript(f.read())
        db.commit()
        db.close()

# Create schema.sql (example)
#

