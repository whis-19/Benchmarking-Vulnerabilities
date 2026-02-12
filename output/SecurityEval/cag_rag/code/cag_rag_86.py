from flask import Flask, request, jsonify
import bcrypt
import os
import secrets
import MySQLdb

app = Flask(__name__)

# Database configuration (read from environment variables)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "mydatabase")

# Salt for password hashing (read from environment variable or generate a new one)
SALT = os.environ.get("SALT")
if not SALT:
    SALT = secrets.token_hex(16)  # Generate a random salt
    os.environ["SALT"] = SALT  # Store the salt in the environment variable
    print("Generated a new salt.  Make sure to persist this in your environment.")


def get_db_connection():
    """
    Establishes a database connection using environment variables.
    """
    try:
        conn = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, charset="utf8", use_unicode=True)
        return conn
    except MySQLdb.Error as e:
        print(f"Error connecting to database: {e}")
        return None


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Hashes the password using bcrypt and stores it securely.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Input validation (example: length constraints)
    if len(username) < 3 or len(username) > 50:
        return jsonify({'error': 'Username must be between 3 and 50 characters'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cursor = conn.cursor()

        # Check if the username already exists using a parameterized query
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({'error': 'Username already exists'}), 409

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the database using a parameterized query
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password.decode('utf-8')))
        conn.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    except MySQLdb.Error as e:
        print(f"Database error: {e}")
        conn.rollback()  # Rollback in case of error
        return jsonify({'error': 'Registration failed'}), 500

    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    # Create the 'users' table if it doesn't exist
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL
                )
            """)
            conn.commit()
        except MySQLdb.Error as e:
            print(f"Error creating table: {e}")
        finally:
            cursor.close()
            conn.close()

    # Use HTTPS in production
    app.run(debug=True, host='0.0.0.0', port=5000)

