import sqlite3
import hashlib
import os
from flask import Flask, request, redirect, url_for, render_template, session

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = 'users.db'

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
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

create_table()  # Ensure the table exists on startup


def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt."""
    if salt is None:
        salt = os.urandom(16).hex()  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password, salt


def register_user(username, password):
    """Registers a new user in the database."""
    hashed_password, salt = hash_password(password)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, hashed_password, salt))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False  # Username already exists


def login(username, password):
    """Authenticates the user against the database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash, salt = result
        hashed_password, _ = hash_password(password, salt)  # Use the stored salt
        if hashed_password == stored_hash:
            return True
    return False


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if register_user(username, password):
            return redirect(url_for('login_page'))  # Redirect to login after successful registration
        else:
            return render_template('register.html', error="Username already exists.")

    return render_template('register.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if login(username, password):
            session['username'] = username  # Store username in session
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')


@app.route('/home')
def home():
    """The home page, accessible only after login."""
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login_page'))  # Redirect to login if not logged in


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login_page'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """Allows a logged-in user to change their password."""
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        username = session['username']
        if login(username, old_password):  # Verify old password
            hashed_password, salt = hash_password(new_password)
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                           (hashed_password, salt, username))
            conn.commit()
            conn.close()
            return render_template('change_password.html', success="Password changed successfully!")
        else:
            return render_template('change_password.html', error="Incorrect old password.")

    return render_template('change_password.html')


# Example templates (create these in a 'templates' folder)

# templates/login.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
</body>
</html>
"""

# templates/register.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h1>Register</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Register">
    </form>
    <p>Already have an account? <a href="{{ url_for('login_page') }}">Login here</a>.</p>
</body>
</html>
"""

# templates/home.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Home</title>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>You are logged in.</p>
    <a href="{{ url_for('change_password') }}">Change Password</a><br>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# templates/change_password.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Change Password</title>
</head>
<body>
    <h1>Change Password</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    {% if success %}
        <p style="color: green;">{{ success }}</p>
    {% endif %}
    <form method="post">
        <label for="old_password">Old Password:</label><br>
        <input type="password" id="old_password" name="old_password"><br><br>
        <label for="new_password">New Password:</label><br>
        <input type="password" id="new_password" name="new_password"><br><br>
        <input type="submit" value="Change Password">
    </form>
    <a href="{{ url_for('home') }}">Back to Home</a>
</body>
</html>
"""


if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production!

