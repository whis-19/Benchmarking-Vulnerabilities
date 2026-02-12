import sqlite3
import hashlib
import os
from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
import secrets  # For generating secure random values

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Securely generate a secret key

# Configuration (Move to a separate config file)
DATABASE = 'users.db'
CONFIG_FILE = 'config.ini'  # Example config file name

# --- Database Initialization and User Management ---

def get_db_connection():
    """Connects to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def create_tables():
    """Creates the users table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'  -- Added role for privilege management
        )
    """)
    conn.commit()
    conn.close()

def create_admin_user():
    """Creates an initial admin user if none exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0:
        # First login mode: Require a strong password
        print("No users found.  Please create an initial admin user.")
        username = input("Enter admin username: ")
        while True:
            password = input("Enter a strong admin password: ")
            if len(password) < 12:  # Example minimum length
                print("Password must be at least 12 characters long.")
            elif not any(char.isdigit() for char in password):
                print("Password must contain at least one digit.")
            elif not any(char.isupper() for char in password):
                print("Password must contain at least one uppercase letter.")
            elif not any(char.islower() for char in password):
                print("Password must contain at least one lowercase letter.")
            elif not any(char in "!@#$%^&*()" for char in password):
                print("Password must contain at least one special character.")
            else:
                break

        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)
        cursor.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                       (username, password_hash, salt, 'admin'))
        conn.commit()
        print("Admin user created successfully.")
    conn.close()


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password

def verify_password(password, saved_hash, salt):
    """Verifies the password against the saved hash and salt."""
    hashed_password = hash_password(password, salt)
    return hashed_password == saved_hash

def get_user_role(username):
    """Retrieves the user's role from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result['role']
    return None

# --- Authentication Decorator ---

def login_required(role=None):
    """Decorator to require login and optionally a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))

            if role:
                user_role = get_user_role(session['username'])
                if user_role != role:
                    return render_template('error.html', message="Unauthorized access.")  # Create an error template

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            saved_hash = result['password_hash']
            salt = result['salt']
            if verify_password(password, saved_hash, salt):
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="Invalid credentials")
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/dashboard')
@login_required()  # Requires login
def dashboard():
    """Displays the dashboard."""
    username = session['username']
    return render_template('dashboard.html', username=username)

@app.route('/admin')
@login_required(role='admin')  # Requires login and admin role
def admin_panel():
    """Displays the admin panel."""
    return render_template('admin.html')

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))

# --- Error Handling ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- Main ---

if __name__ == '__main__':
    create_tables()
    create_admin_user()  # Create initial admin user if none exist
    app.run(debug=True)

