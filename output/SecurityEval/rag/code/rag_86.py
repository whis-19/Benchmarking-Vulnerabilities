from flask import Flask, request, jsonify
import MySQLdb
import hashlib
import os
import secrets

app = Flask(__name__)

# Load database configuration from environment variables
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "mydatabase")
DB_PORT = int(os.environ.get("DB_PORT", 3306))  # Ensure port is an integer


def get_db_connection():
    """
    Establishes a database connection using environment variables.
    """
    try:
        conn = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, port=DB_PORT, charset="utf8", use_unicode=True)
        return conn
    except MySQLdb.Error as e:
        print(f"Error connecting to database: {e}")
        return None


def hash_password(password, salt=None):
    """Hashes the password using a salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', salted_password, salt.encode('utf-8'), 100000)
    return salt, hashed_password.hex()


def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salted_password = stored_salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', salted_password, stored_salt.encode('utf-8'), 100000)
    return hashed_password.hex() == stored_hash


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Hashes the password before storing it in the database.
    Uses parameterized queries to prevent SQL injection.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cursor = conn.cursor()

    try:
        # Check if the username already exists
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400

        # Hash the password
        salt, hashed_password = hash_password(password)

        # Insert the new user into the database
        cursor.execute("INSERT INTO users (username, password, salt) VALUES (%s, %s, %s)",
                       (username, hashed_password, salt))
        conn.commit()
        conn.close()

        return jsonify({'message': 'User registered successfully'}), 201

    except MySQLdb.Error as e:
        conn.rollback()
        conn.close()
        print(f"Database error: {e}")
        return jsonify({'error': 'Failed to register user'}), 500


@app.route('/login', methods=['POST'])
def login():
    """
    Logs in an existing user.  Verifies the password against the stored hash.
    Uses parameterized queries to prevent SQL injection.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cursor = conn.cursor()

    try:
        # Retrieve the user from the database
        cursor.execute("SELECT username, password, salt FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({'error': 'Invalid username or password'}), 401

        stored_username, stored_hash, stored_salt = user

        # Verify the password
        if verify_password(stored_salt, stored_hash, password):
            conn.close()
            return jsonify({'message': 'Login successful'}), 200
        else:
            conn.close()
            return jsonify({'error': 'Invalid username or password'}), 401

    except MySQLdb.Error as e:
        conn.close()
        print(f"Database error: {e}")
        return jsonify({'error': 'Failed to login'}), 500


if __name__ == '__main__':
    # Create the 'users' table if it doesn't exist
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL
            )
        """)
        conn.commit()
        conn.close()
    else:
        print("Failed to create table.  Check database connection.")

    app.run(debug=True)

