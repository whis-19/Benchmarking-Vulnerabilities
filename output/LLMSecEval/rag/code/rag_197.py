import os
from flask import Flask, render_template, session, redirect, url_for, request, abort
from functools import wraps
import bcrypt
import secrets
import hashlib
from cryptography.fernet import Fernet
import sqlite3

app = Flask(__name__)

# Security: Generate a random secret key for the session
app.secret_key = secrets.token_hex(32)

# Database setup (using SQLite for simplicity, consider a more robust solution for production)
DATABASE = 'user_data.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database if it doesn't exist
if not os.path.exists(DATABASE):
    init_db()

# Encryption Key (Store securely - e.g., environment variable, KMS)
#  NEVER hardcode encryption keys in your source code.
#  This is just for demonstration purposes.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("Warning: ENCRYPTION_KEY not set in environment.  Generating a temporary key.  DO NOT USE IN PRODUCTION.")
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"Temporary Encryption Key: {ENCRYPTION_KEY.decode()}") # Only for demonstration!
    print("Set the ENCRYPTION_KEY environment variable for production use.")
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)


# --- Helper Functions ---

def encrypt_data(data: str) -> bytes:
    """Encrypts sensitive data using Fernet."""
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes) -> str:
    """Decrypts sensitive data using Fernet."""
    return fernet.decrypt(encrypted_data).decode()

def hash_password(password: str) -> bytes:
    """Hashes the password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password: str, hashed_password: bytes) -> bool:
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def get_user_data(username):
    """Retrieves user data from the database."""
    db = get_db()
    cur = db.execute("SELECT username, email, ssn_last_4 FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    cur.close()
    return user

# --- Authentication Decorator ---

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))  # Redirect to login with 'next' URL
        return f(*args, **kwargs)
    return decorated_function


# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        ssn_last_4 = request.form['ssn_last_4']

        # Input validation (add more robust validation as needed)
        if not (username and password and email and ssn_last_4):
            return render_template('register.html', error='All fields are required.')

        # Hash the password
        hashed_password = hash_password(password)

        # Encrypt sensitive data
        encrypted_email = encrypt_data(email)
        encrypted_ssn_last_4 = encrypt_data(ssn_last_4)

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password, email, ssn_last_4) VALUES (?, ?, ?, ?)",
                (username, hashed_password, encrypted_email, encrypted_ssn_last_4)
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists.')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.execute("SELECT username, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            stored_username, stored_password_hash = user
            if verify_password(password, stored_password_hash):
                session['username'] = stored_username
                next_url = request.args.get('next')
                return redirect(next_url or url_for('info'))  # Redirect to 'next' or 'info'
            else:
                return render_template('login.html', error='Invalid credentials.')
        else:
            return render_template('login.html', error='Invalid credentials.')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/info')
@login_required
def info():
    """Displays user information (username, email, last 4 SSN)."""
    username = session['username']
    user = get_user_data(username)

    if user:
        username, encrypted_email, encrypted_ssn_last_4 = user
        email = decrypt_data(encrypted_email)
        ssn_last_4 = decrypt_data(encrypted_ssn_last_4)

        #  NEVER log sensitive information.
        #  app.logger.info(f"User {username} accessed /info") # BAD!

        return render_template('info.html', username=username, email=email, ssn_last_4=ssn_last_4)
    else:
        # Handle the case where the user is not found (shouldn't happen if login_required is working)
        return "User not found", 404


if __name__ == '__main__':
    #  DO NOT use debug=True in production.  It can expose sensitive information.
    #  Use a production WSGI server like gunicorn or uWSGI.
    from flask import g
    app.run(debug=True)

