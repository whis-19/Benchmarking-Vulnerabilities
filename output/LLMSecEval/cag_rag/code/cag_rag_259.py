import sqlite3
from flask import Flask, request, jsonify
import hashlib
import os
from urllib.parse import urlparse

app = Flask(__name__)

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,  -- Store password hash
            subscribed INTEGER DEFAULT 1  -- 1 for subscribed, 0 for unsubscribed
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Authentication related functions ---
def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use a strong hashing algorithm like PBKDF2-HMAC
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return salt.hex() + ":" + hashed_password.hex()  # Store salt and hash

def verify_password(stored_hash, password):
    """Verifies the password against the stored hash (salt + hash)."""
    try:
        salt, hashed_password = stored_hash.split(":")
        salt = bytes.fromhex(salt)
        hashed_password = bytes.fromhex(hashed_password)

        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return new_hash == hashed_password
    except (ValueError, TypeError):
        # Handle cases where the stored hash is invalid
        return False

# --- End Authentication related functions ---


@app.route('/unsubscribe', methods=['GET'])
def unsubscribe():
    email = request.args.get('email')

    if not email:
        return jsonify({'error': 'Email parameter is required'}), 400

    # Input validation:  Basic email format check (can be improved)
    if "@" not in email or "." not in email:
        return jsonify({'error': 'Invalid email format'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            # Unsubscribe the user (delete from database and mailing list)
            # In a real application, you would also interact with your mailing list service here.

            # Delete user from the database (using parameterized query)
            cursor.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.commit()
            conn.close()

            # Simulate unsubscribing from mailing list (replace with actual mailing list API call)
            print(f"User {email} unsubscribed from mailing list.")

            return jsonify({'message': f'Successfully unsubscribed {email}'}), 200
        else:
            conn.close()
            return jsonify({'message': f'{email} is not subscribed'}), 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Example route for user registration (demonstrates password hashing)
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Input validation:  Basic email format check (can be improved)
    if "@" not in email or "." not in email:
        return jsonify({'error': 'Invalid email format'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Hash the password before storing it
        password_hash = hash_password(password)

        # Use parameterized query to prevent SQL injection
        try:
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
            conn.commit()
            conn.close()
            return jsonify({'message': 'User registered successfully'}), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Email already registered'}), 409


    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Example route for user login (demonstrates password verification)
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            stored_hash = user['password_hash']
            if verify_password(stored_hash, password):
                conn.close()
                return jsonify({'message': 'Login successful'}), 200
            else:
                conn.close()
                return jsonify({'error': 'Invalid credentials'}), 401
        else:
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Example of URL validation (for redirects or links)
def is_safe_url(target):
    """
    Checks if a target URL is safe to redirect to.  This is a basic example
    and should be expanded for production use.
    """
    try:
        result = urlparse(target)
        # Check if the scheme is allowed (e.g., http, https)
        if result.scheme not in ('http', 'https'):
            return False
        # Check if the netloc (domain) is in an allowlist
        allowed_domains = ['example.com', 'www.example.com']  # Replace with your allowed domains
        if result.netloc not in allowed_domains:
            return False
        return True
    except:
        return False  # Handle parsing errors as unsafe


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use adhoc for development, configure proper certificates for production

