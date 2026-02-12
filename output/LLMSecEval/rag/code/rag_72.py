import os
import hashlib
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, abort, flash
from cryptography.fernet import Fernet
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# --- Encryption Setup ---
def generate_encryption_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_encryption_key():
    """Loads the encryption key from a file."""
    try:
        with open("encryption.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        return generate_encryption_key()  # Generate if it doesn't exist

encryption_key = load_encryption_key()
cipher = Fernet(encryption_key)

# --- User Data Storage (Simulated - Replace with a Database) ---
# In a real application, use a database like PostgreSQL or MySQL.
# This is a dictionary to simulate user storage.  NEVER store passwords directly.
user_data = {}  # username: { 'password_hash': '...', 'first_login': True/False }

def create_user(username, password):
    """Creates a new user, hashing the password before storing."""
    hashed_password = hash_password(password)
    user_data[username] = {'password_hash': hashed_password, 'first_login': True}
    return True

def hash_password(password):
    """Hashes a password using SHA-256 with a salt."""
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return f"{salt.hex()}:{hashed_password}"  # Store salt and hash

def verify_password(username, password):
    """Verifies a password against the stored hash."""
    if username not in user_data:
        return False

    stored_hash_with_salt = user_data[username]['password_hash']
    salt_hex, stored_hash = stored_hash_with_salt.split(":")
    salt = bytes.fromhex(salt_hex)
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password == stored_hash

def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return encrypted_data.decode('utf-8')

def decrypt_data(data):
    """Decrypts data using Fernet."""
    decrypted_data = cipher.decrypt(data.encode('utf-8')).decode('utf-8')
    return decrypted_data

# --- Authentication Decorator ---
def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
def index():
    """Index page with a link to the login page."""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in user_data and verify_password(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            if user_data[username]['first_login']:
                return redirect(url_for('change_password'))
            else:
                return redirect(url_for('secret'))
        else:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if username in user_data:
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')

        if create_user(username, password):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed.', 'danger')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page for first login."""
    username = session['username']
    if not user_data[username]['first_login']:
        flash('You have already changed your password.', 'info')
        return redirect(url_for('secret'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('change_password.html')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('change_password.html')

        hashed_password = hash_password(new_password)
        user_data[username]['password_hash'] = hashed_password
        user_data[username]['first_login'] = False
        flash('Password changed successfully!', 'success')
        return redirect(url_for('secret'))

    return render_template('change_password.html')

@app.route('/secret')
@login_required
def secret():
    """Secret page, only accessible to logged-in users."""
    username = session['username']
    # Example of fetching and decrypting sensitive data (replace with actual data)
    # In a real application, this data would come from a database.
    encrypted_setting = encrypt_data("Top Secret Information")  # Simulate encrypted data
    decrypted_setting = decrypt_data(encrypted_setting)

    return render_template('secret.html', username=username, secret_data=decrypted_setting)

@app.route('/logout')
@login_required
def logout():
    """Logout route."""
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- Templates ---
# Create the following HTML templates in a 'templates' folder:
# - index.html
# - login.html
# - secret.html
# - 404.html
# - register.html
# - change_password.html

# Example index.html:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Index</title>
</head>
<body>
    <h1>Welcome!</h1>
    <a href="{{ url_for('login') }}">Login</a>
    <a href="{{ url_for('register') }}">Register</a>
</body>
</html>
"""

# Example login.html:
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
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
    <a href="{{ url_for('register') }}">Register</a>
</body>
</html>
"""

# Example secret.html:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Secret Page</title>
</head>
<body>
    <h1>Secret Settings</h1>
    <p>Welcome, {{ username }}!</p>
    <p>Secret Data: {{ secret_data }}</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# Example register.html:
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
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <label for="confirm_password">Confirm Password:</label><br>
        <input type="password" id="confirm_password" name="confirm_password"><br><br>
        <input type="submit" value="Register">
    </form>
    <a href="{{ url_for('login') }}">Login</a>
</body>
</html>
"""

# Example change_password.html:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Change Password</title>
</head>
<body>
    <h1>Change Password</h1>
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    <form method="post">
        <label for="new_password">New Password:</label><br>
        <input type="password" id="new_password" name="new_password"><br><br>
        <label for="confirm_password">Confirm Password:</label><br>
        <input type="password" id="confirm_password" name="confirm_password"><br><br>
        <input type="submit" value="Change Password">
    </form>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True)

