from flask import Flask, request, jsonify
import MySQLdb
import hashlib
import os

app = Flask(__name__)

# Database configuration -  IMPORTANT: Use environment variables for sensitive data
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
DB_USER = os.environ.get("DB_USER", "root")  # Default to root if not set
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")  # Default to empty string if not set
DB_NAME = os.environ.get("DB_NAME", "mydatabase")  # Default to mydatabase if not set


def get_db_connection():
    """
    Establishes a database connection using environment variables for credentials.
    Handles potential connection errors gracefully.
    """
    try:
        conn = MySQLdb.connect(host=DB_HOST,
                               user=DB_USER,
                               passwd=DB_PASSWORD,
                               db=DB_NAME,
                               charset="utf8",
                               use_unicode=True)
        return conn
    except MySQLdb.Error as e:
        print(f"Database connection error: {e}")  # Log the error
        return None  # Return None to indicate connection failure


def hash_password(password):
    """
    Hashes the password using SHA-256 with a randomly generated salt.
    """
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')  # Concatenate salt and password
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt.hex() + ":" + hashed_password  # Store salt and hash separated by a colon


def verify_password(stored_password, provided_password):
    """
    Verifies a provided password against a stored hashed password (including salt).
    """
    try:
        salt, hashed_password = stored_password.split(":")
        salt = bytes.fromhex(salt)
        salted_password = salt + provided_password.encode('utf-8')
        new_hashed_password = hashlib.sha256(salted_password).hexdigest()
        return new_hashed_password == hashed_password
    except (ValueError, TypeError):
        return False  # Handle cases where the stored password format is invalid


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Expects JSON data with 'username' and 'password'.
    Validates input, checks for existing users, hashes the password with a salt,
    and inserts the user into the database.  Uses parameterized queries to prevent SQL injection.
    Returns a JSON response indicating success or failure.
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Input validation
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        if len(username) < 3 or len(username) > 50:
            return jsonify({'message': 'Username must be between 3 and 50 characters'}), 400

        if len(password) < 8:
            return jsonify({'message': 'Password must be at least 8 characters'}), 400


        conn = get_db_connection()
        if not conn:
            return jsonify({'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if username already exists (using parameterized query)
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            conn.close()
            return jsonify({'message': 'Username already exists'}), 409  # Conflict

        # Hash the password
        hashed_password = hash_password(password)

        # Insert the new user (using parameterized query)
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'message': 'User registered successfully'}), 201  # Created
        except MySQLdb.Error as e:
            conn.rollback()  # Rollback in case of error
            cursor.close()
            conn.close()
            print(f"Database error during registration: {e}") # Log the error
            return jsonify({'message': 'Database error during registration'}), 500

    except Exception as e:
        print(f"Error during registration: {e}") # Log the error
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/login', methods=['POST'])
def login():
    """
    Logs in an existing user.  Expects JSON data with 'username' and 'password'.
    Retrieves the user from the database, verifies the password, and returns a success message.
    Uses parameterized queries to prevent SQL injection.
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Retrieve the user from the database (using parameterized query)
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({'message': 'Invalid username or password'}), 401  # Unauthorized

        stored_password = user[0]

        # Verify the password
        if verify_password(stored_password, password):
            cursor.close()
            conn.close()
            return jsonify({'message': 'Login successful'}), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({'message': 'Invalid username or password'}), 401

    except Exception as e:
        print(f"Error during login: {e}") # Log the error
        return jsonify({'message': 'Internal server error'}), 500


if __name__ == '__main__':
    # Create the 'users' table if it doesn't exist
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL
                )
            """)
            conn.commit()
        except MySQLdb.Error as e:
            print(f"Error creating table: {e}")
        finally:
            cursor.close()
            conn.close()

    app.run(debug=True)  #  Set debug=False in production

