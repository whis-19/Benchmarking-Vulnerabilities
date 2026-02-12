import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Database Configuration (Important: Use environment variables for sensitive data)
DATABASE_PATH = os.environ.get("DATABASE_PATH", "database.db")  # Default to 'database.db' if not set
SECRET_KEY = os.environ.get("SECRET_KEY", "your_secret_key")  # Change this to a strong, random key!
app.config['SECRET_KEY'] = SECRET_KEY

# --- Database Initialization (Run this once to create the database and table) ---
def initialize_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_moderator INTEGER DEFAULT 0  -- 0 for False, 1 for True
        )
    """)
    conn.commit()
    conn.close()

# --- Example: Add an initial moderator (Run this once) ---
def create_initial_moderator(username, password):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    try:
        cursor.execute("INSERT INTO users (username, password_hash, is_moderator) VALUES (?, ?, ?)",
                       (username, hashed_password, 1))
        conn.commit()
        print(f"Moderator '{username}' created successfully.")
    except sqlite3.IntegrityError:
        print(f"User '{username}' already exists.")
    finally:
        conn.close()


# --- Route to check moderator status ---
@app.route("/check_moderator", methods=["POST"])
def check_moderator():
    """
    Checks if a user is a moderator based on username and password.
    Requires username and password in the request body (JSON).
    """
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash, is_moderator FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        conn.close()

        if result:
            password_hash, is_moderator = result
            if check_password_hash(password_hash, password):
                return jsonify({"is_moderator": bool(is_moderator)})  # Convert to boolean
            else:
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        print(f"Error: {e}")  # Log the error for debugging
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Initialize the database if it doesn't exist
    initialize_database()

    # Example: Create an initial moderator (only run this once)
    # create_initial_moderator("admin", "secure_password")  # Replace with a strong password

    app.run(debug=True)  # Disable debug mode in production!

