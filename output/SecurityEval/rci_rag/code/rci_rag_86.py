from flask import Flask, request, jsonify
# import MySQLdb  # Deprecated - REMOVE THIS
import mysql.connector  # Or pymysql - MUST USE ONE OF THESE
import hashlib
import os
import secrets
import re
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_session import Session  # For session management

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['WTF_CSRF_ENABLED'] = True  # Uncomment to enable CSRF protection
csrf = CSRFProtect(app)  # Uncomment to enable CSRF protection

# Session configuration (if using sessions)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "redis"  # Or "memcached"
# Configure Redis or Memcached connection details here
# app.config["SESSION_REDIS"] = redis.Redis(host='localhost', port=6379)
Session(app)


# ... (Database configuration from environment variables) ...


def get_db_connection():
    """Establish a database connection."""
    try:
        conn = mysql.connector.connect(  # Or pymysql.connect
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            ssl_disabled=True,  # Explicitly disable SSL if not needed.  Enable if required.  ENABLE IN PRODUCTION!
            charset="utf8mb4",  # Use a character set that supports a wide range of characters
            use_unicode=True
        )
        return conn
    except mysql.connector.Error as e:  # Or pymysql.MySQLError
        print(f"Database connection error: {e}")
        return None


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    username = request.form.get('username')
    password = request.form.get('password')

    # ... (Validation code - keep this) ...

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            conn.close()
            print(f"Registration attempt with existing username: {username}") # Log the attempt
            return jsonify({'message': 'Registration failed'}), 200  # Generic message, log specific error

        # Hash the password using bcrypt (or Argon2)
        hashed_password = generate_password_hash(password)

        # Store the hashed password in the database
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                       (username, hashed_password))
        conn.commit()

        cursor.close()
        conn.close()
        return jsonify({'message': 'Registration successful'}), 200 # Generic success message

    except mysql.connector.Error as e:  # Or pymysql.MySQLError
        print(f"Database error: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        if conn:
            conn.close()

# ... (Login and error handler - keep these, but remember to enable SSL in production) ...

