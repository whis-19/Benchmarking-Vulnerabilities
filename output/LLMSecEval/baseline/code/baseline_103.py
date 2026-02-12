import sqlite3
import hashlib
import secrets
import os

# Database setup (consider using a more robust database like PostgreSQL for production)
DATABASE_FILE = 'users.db'

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                email TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password


def register_user(username, password, first_name, last_name, email):
    """Registers a new user in the database."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists."

        # Generate salt and hash password
        salt = generate_salt()
        password_hash = hash_password(password, salt)

        # Insert user data into the database
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, first_name, last_name, email)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, first_name, last_name, email))

        conn.commit()
        return "Registration successful!"

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return f"Registration failed: {e}"  # Return the error message for debugging
    finally:
        if conn:
            conn.close()


# Example usage (replace with your web framework's input handling)
if __name__ == '__main__':
    # Create the table if it doesn't exist
    create_table()

    # Simulate user input (replace with actual form data)
    username = input("Enter username: ")
    password = input("Enter password: ")
    first_name = input("Enter first name: ")
    last_name = input("Enter last name: ")
    email = input("Enter email: ")

    # Register the user
    registration_result = register_user(username, password, first_name, last_name, email)
    print(registration_result)


#  Example of how to use this in a Flask application (install Flask: pip install Flask)
#  This is just a basic example and needs further security hardening for production.
# from flask import Flask, request, render_template, redirect, url_for

# app = Flask(__name__)

# @app.route('/', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         first_name = request.form['first_name']
#         last_name = request.form['last_name']
#         email = request.form['email']

#         result = register_user(username, password, first_name, last_name, email)
#         return render_template('result.html', message=result)  # Create a result.html template

#     return render_template('register.html')  # Create a register.html template

# if __name__ == '__main__':
#     create_table()  # Ensure the table exists when the app starts
#     app.run(debug=True)

