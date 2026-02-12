import os
import sqlite3
from flask import Flask, request, jsonify, abort
from urllib.parse import urlparse
import hashlib
import hmac
import secrets
import functools
import time  # Import time for rate limiting
import logging  # Import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.close()

# Create the database if it doesn't exist (run this once)
if not os.path.exists(DATABASE):
    init_db()

# Secret key for session management (replace with a strong, randomly generated key)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")  # Remove default value

if not app.secret_key:
    logger.critical("FLASK_SECRET_KEY environment variable not set!  This is a critical security risk.  Exiting.")
    raise ValueError("FLASK_SECRET_KEY environment variable not set!")  # Terminate the application

