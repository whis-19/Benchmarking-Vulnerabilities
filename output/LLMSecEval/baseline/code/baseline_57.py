import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a strong, random key!

DATABASE = 'users.db'

# --- Database Initialization ---
def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()  # Create the table if it doesn't exist

# --- Hashing Function ---
def hash_password(password):
    """Hashes the password using SHA-256."""
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password

# --- User Authentication Functions ---
def register_user(username, password):
    """Registers a new user in the database."""
    hashed_password = hash_password(password)
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        return False # Username already exists

def authenticate_user(username, password):
    """Authenticates a user against the database."""
    hashed_password = hash_password(password)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()
    conn.close()
    return user  # Returns the user tuple if found, None otherwise

# --- Flask Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)

        if user:
            session['username'] = username  # Store username in session
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if register_user(username, password):
            return redirect(url_for('login'))  # Redirect to login after successful registration
        else:
            return render_template('register.html', error='Username already exists')

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login'))

# --- Template Files ---
# Create the following HTML files in a 'templates' folder:
# - login.html
# - register.html
# - dashboard.html

# login.html
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
    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
</body>
</html>
"""

# register.html
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
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
</body>
</html>
"""

# dashboard.html
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
    app.run(debug=True)

