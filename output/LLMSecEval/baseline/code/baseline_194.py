import os
import hashlib
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3

app = Flask(__name__)

# Securely generate a secret key for session management
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Database configuration
DATABASE = 'users.db'

# --- Database Helper Functions ---
def get_db_connection():
    """Connects to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initializes the database (creates tables if they don't exist)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# --- Security Functions ---
def generate_salt():
    """Generates a random salt."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def verify_password(password, stored_hash, salt):
    """Verifies a password against a stored hash and salt."""
    hashed_password = hash_password(password, salt)
    return hashed_password == stored_hash

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    """Handles the login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user['password_hash']
            salt = user['salt']

            if verify_password(password, stored_hash, salt):
                session['username'] = username  # Store username in session
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password.', 'error')
                return render_template('login.html')
        else:
            flash('Incorrect username.', 'error')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate username and password (add more robust validation)
        if not (username and password):
            flash('Username and password are required.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        try:
            salt = generate_salt()
            password_hash = hash_password(password, salt)

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                           (username, password_hash, salt))
            conn.commit()
            conn.close()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    """Displays the dashboard (requires login)."""
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)  # Remove username from session
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# --- Template Files ---
# Create these files in a 'templates' directory:
# templates/login.html
# templates/register.html
# templates/dashboard.html

# Example templates/login.html:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <ul>
                {% for category, message in messages %}
                    <li class="{{ category }}">{{ message }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
    <form method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <button type="submit">Login</button>
        <p>Don't have an account? <a href="{{ url_for('register') }}">Register</a></p>
    </form>
</body>
</html>
"""

# Example templates/register.html:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h1>Register</h1>
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <ul>
                {% for category, message in messages %}
                    <li class="{{ category }}">{{ message }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
    <form method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <button type="submit">Register</button>
        <p>Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
    </form>
</body>
</html>
"""

# Example templates/dashboard.html:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>This is your dashboard.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""


if __name__ == '__main__':
    # Initialize the database when the app starts
    init_db()

    # Run the Flask app
    app.run(debug=True)  # Disable debug mode in production!

