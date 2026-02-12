import os
import hashlib
import secrets
from functools import wraps
from flask import Flask, session, redirect, url_for, request, abort
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(24))  # Use a strong, randomly generated secret key.  Fallback to a random key if not in .env

# Configuration (moved to environment variables or a separate config file)
# Example using environment variables:
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///:memory:")  # Replace with your actual database URL
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID", "1")  # Replace with the actual admin user ID (from the database)

# Dummy user database (replace with a real database interaction)
# In a real application, use a database like PostgreSQL, MySQL, or SQLite.
# Use an ORM like SQLAlchemy for secure database interactions.
users = {
    "1": {  # User ID
        "username": "user1",
        "password_hash": "",  # Store password hash, not the plain text password
        "is_admin": False,
        "first_login": True  # Flag for first login
    },
    "2": {
        "username": "admin",
        "password_hash": "",  # Store password hash, not the plain text password
        "is_admin": True,
        "first_login": True
    }
}

# Function to hash a password using pbkdf2_hmac
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Use pbkdf2_hmac for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password.encode('utf-8'),  # Convert password to bytes
        salt.encode('utf-8'),  # Convert salt to bytes
        100000  # Number of iterations (adjust as needed)
    )
    return salt, hashed_password.hex()  # Return salt and hashed password

# Function to verify a password against a stored hash
def verify_password(password, stored_salt, stored_hash):
    salt, hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user_id = session['user_id']
        user = users.get(user_id)
        if not user or not user['is_admin']:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    user = users.get(user_id)

    if user['is_admin']:
        return redirect(url_for('admin_page'))
    else:
        return redirect(url_for('user_page'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username (replace with database query)
        user_id = None
        for uid, user_data in users.items():
            if user_data['username'] == username:
                user_id = uid
                break

        if user_id:
            user = users[user_id]
            if user['first_login']:
                return "Please set a new password on first login." #Redirect to first login page
            
            stored_salt = user.get('password_salt', '')
            stored_hash = user.get('password_hash', '')

            if verify_password(password, stored_salt, stored_hash):
                session['user_id'] = user_id
                return redirect(url_for('index'))
            else:
                return "Invalid credentials"
        else:
            return "Invalid credentials"

    return '''
        <form method="post">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><button type="submit">Log In</button></p>
        </form>
    '''

@app.route('/first_login', methods=['GET', 'POST'])
def first_login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "Passwords do not match."

        if user_id and user_id in users:
            user = users[user_id]
            if user['first_login']:
                salt, hashed_password = hash_password(new_password)
                user['password_salt'] = salt
                user['password_hash'] = hashed_password
                user['first_login'] = False
                return redirect(url_for('login'))
            else:
                return "User is not in first login mode."
        else:
            return "Invalid user ID."

    # In a real application, you would pass the user_id to this page securely.
    # For example, after successful registration.
    return '''
        <form method="post">
            <input type="hidden" name="user_id" value="1">  <!-- Replace with actual user ID -->
            <p>New Password: <input type="password" name="new_password"></p>
            <p>Confirm Password: <input type="password" name="confirm_password"></p>
            <p><button type="submit">Set Password</button></p>
        </form>
    '''

@app.route('/user_page')
@login_required
def user_page():
    user_id = session['user_id']
    user = users.get(user_id)
    return f"Welcome, {user['username']}!"

@app.route('/admin_page')
@admin_required
def admin_page():
    return "Welcome to the admin page!"

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Example registration route (replace with a proper implementation)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Basic validation (add more robust validation)
        if not username or not password:
            return "Username and password are required."

        # Check if username already exists (replace with database query)
        for user_data in users.values():
            if user_data['username'] == username:
                return "Username already exists."

        # Create a new user (replace with database insertion)
        new_user_id = str(len(users) + 1)  # Simple ID generation
        salt, hashed_password = hash_password(password)
        users[new_user_id] = {
            "username": username,
            "password_salt": salt,
            "password_hash": hashed_password,
            "is_admin": False,
            "first_login": False
        }

        # Redirect to first login page
        return redirect(url_for('login'))

    return '''
        <form method="post">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><button type="submit">Register</button></p>
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)

