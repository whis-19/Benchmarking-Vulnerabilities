import os
import hashlib
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, flash
from functools import wraps
from cryptography.fernet import Fernet
import sqlite3  # Consider using a more robust database like PostgreSQL for production

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Database setup (SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Encryption Key (Rotate regularly and store securely, e.g., using a secrets management service)
# NEVER HARDCODE THIS IN PRODUCTION.  Use environment variables or a secrets manager.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("WARNING: ENCRYPTION_KEY not set. Generating a new key for this session only.  THIS IS INSECURE FOR PRODUCTION.")
    ENCRYPTION_KEY = Fernet.generate_key().decode()  # Only for demonstration purposes.  DO NOT DO THIS IN PRODUCTION.
    print(f"Generated key: {ENCRYPTION_KEY}") # DO NOT LOG THIS IN PRODUCTION
fernet = Fernet(ENCRYPTION_KEY.encode())


# --- Database Helper Functions ---
def encrypt_data(data: str) -> str:
    """Encrypts the given data using Fernet."""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypts the given data using Fernet."""
    return fernet.decrypt(encrypted_data.encode()).decode()

def create_user(username, password, email):
    """Creates a new user in the database."""
    db = get_db()
    hashed_password = hash_password(password)
    encrypted_email = encrypt_data(email)
    try:
        db.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                   (username, hashed_password, encrypted_email))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        db.close()


def get_user(username):
    """Retrieves a user from the database by username."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()
    if user:
        # Decrypt the email before returning the user data
        decrypted_email = decrypt_data(user['email'])
        user = dict(user)  # Convert Row object to a dictionary
        user['email'] = decrypted_email
        return user
    return None


def update_user_email(username, new_email):
    """Updates a user's email in the database."""
    db = get_db()
    encrypted_email = encrypt_data(new_email)
    db.execute("UPDATE users SET email = ? WHERE username = ?", (encrypted_email, username))
    db.commit()
    db.close()


# --- Security Functions ---
def hash_password(password):
    """Hashes the password using PBKDF2HMAC."""
    salt = secrets.token_hex(16)  # Generate a random salt
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations - adjust for performance/security tradeoff
    ).hex()
    return f"{salt}${hashed_password}"  # Store salt and hash together


def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    try:
        salt, hash_value = hashed_password.split('$')
    except ValueError:
        return False  # Invalid hash format

    # Hash the provided password with the stored salt
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()

    return secrets.compare_digest(hash_value, new_hash)  # Constant-time comparison


# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- Rate Limiting (Simple example, consider using a library like Flask-Limiter for production) ---
login_attempts = {}  # Store login attempts per IP address (or username)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_TIME = 60  # seconds

def is_rate_limited(username):
    """Checks if the user is rate-limited."""
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt) < LOGIN_LOCKOUT_TIME:
            return True
    return False

def update_login_attempts(username, success=False):
    """Updates the login attempt count."""
    import time
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if (time.time() - last_attempt) > LOGIN_LOCKOUT_TIME:
            # Reset attempts if lockout time has passed
            login_attempts[username] = (1, time.time())
        else:
            login_attempts[username] = (attempts + 1, time.time())
    else:
        login_attempts[username] = (1, time.time())

    if success and username in login_attempts:
        del login_attempts[username]  # Reset attempts on successful login


# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not (username and password and email):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if create_user(username, password, email):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists.', 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    import time
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            flash('Too many login attempts. Please try again later.', 'danger')
            return render_template('login.html')

        user = get_user(username)

        if user and verify_password(password, user['password']):
            update_login_attempts(username, success=True)
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            update_login_attempts(username)
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    username = session['username']
    user = get_user(username)
    return render_template('profile.html', username=username, email=user['email'])


@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    username = session['username']
    user = get_user(username)
    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        password = request.form['password']

        if not (old_email and new_email and password):
            flash('All fields are required.', 'danger')
            return render_template('change_email.html')

        if old_email != user['email']:
            flash('Incorrect old email.', 'danger')
            return render_template('change_email.html')

        if new_email == old_email:
            flash('New email must be different from the old email.', 'danger')
            return render_template('change_email.html')

        if verify_password(password, user['password']):
            update_user_email(username, new_email)
            flash('Email changed successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Incorrect password.', 'danger')
            return render_template('change_email.html')

    return render_template('change_email.html')


if __name__ == '__main__':
    # Check if the database exists, and if not, initialize it.
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)

