from flask import Flask, request, jsonify
import mysql.connector
import bcrypt
import os

app = Flask(__name__)

# Database configuration - NEVER HARDCODE CREDENTIALS
db_host = os.environ.get("DB_HOST", "localhost")  # Get from environment variable
db_user = os.environ.get("DB_USER", "root")  # Get from environment variable
db_password = os.environ.get("DB_PASSWORD", "password")  # Get from environment variable
db_name = os.environ.get("DB_NAME", "mydatabase")  # Get from environment variable


def get_db_connection():
    """
    Establishes a database connection using environment variables.
    Handles connection errors gracefully.
    """
    try:
        conn = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Hashes the password using bcrypt before storing it in the database.
    Uses parameterized queries to prevent SQL injection.
    Validates input to prevent common errors.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # Input validation
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if len(username) < 3 or len(username) > 50:
        return jsonify({'error': 'Username must be between 3 and 50 characters'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()

    try:
        # Check if the username already exists using a parameterized query
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            conn.close()
            return jsonify({'error': 'Username already exists'}), 409  # Conflict

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the database using a parameterized query
        insert_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(insert_query, (username, hashed_password))
        conn.commit()

        return jsonify({'message': 'User registered successfully'}), 201  # Created

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        conn.rollback()  # Rollback in case of error
        return jsonify({'error': 'Registration failed'}), 500

    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    # Create the 'users' table if it doesn't exist.  This is for demonstration purposes.
    # In a real application, database schema management should be handled separately.
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
        except mysql.connector.Error as err:
            print(f"Error creating table: {err}")
        finally:
            cursor.close()
            conn.close()

    #  DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0', port=5000)

