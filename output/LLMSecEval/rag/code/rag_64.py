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
# NEVER hardcode encryption keys in your source code.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("ERROR: ENCRYPTION_KEY environment variable not set.  Generating a new key for demonstration purposes ONLY.  DO NOT USE THIS IN PRODUCTION.")
    ENCRYPTION_KEY = Fernet.generate_key().decode() # Insecure - for demonstration only
    print(f"Generated key: {ENCRYPTION_KEY}")
    print("Store this key securely (e.g., environment variable) and restart the application.")
    #exit() # Uncomment to force proper key configuration
fernet = Fernet(ENCRYPTION_KEY.encode())


# --- Helper Functions ---

def encrypt_data(data: str) -> str:
    """Encrypts the given data using Fernet."""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data: str) -> str:
    """Decrypts the given data using Fernet."""
    return fernet.decrypt(data.encode()).decode()

def hash_password(password: str) -> bytes:
    """Hashes the password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password: str, hashed_password: bytes) -> bool:
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def get_user_data(username):
    """Retrieves user data from the database."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username, email, ssn_last_4, password FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    cur.close()
    return user

# --- Authentication Decorator ---

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
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

        # Input validation (add more robust validation)
        if not (username and password and email and ssn_last_4):
            return render_template('register.html', error='All fields are required.')

        # Hash the password
        hashed_password = hash_password(password)

        # Encrypt sensitive data
        encrypted_email = encrypt_data(email)
        encrypted_ssn_last_4 = encrypt_data(ssn_last_4)

        try:
            db = get_db()
            cur = db.cursor()
            cur.execute("INSERT INTO users (username, password, email, ssn_last_4) VALUES (?, ?, ?, ?)",
                        (username, hashed_password, encrypted_email, encrypted_ssn_last_4))
            db.commit()
            cur.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists.')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_data(username)

        if user:
            stored_username, stored_email, stored_ssn_last_4, stored_password = user
            if verify_password(password, stored_password):
                session['username'] = username
                next_url = request.args.get('next')
                return redirect(next_url or url_for('info'))
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
        stored_username, encrypted_email, encrypted_ssn_last_4, stored_password = user
        email = decrypt_data(encrypted_email)
        ssn_last_4 = decrypt_data(encrypted_ssn_last_4)

        # Security:  Do not cache sensitive information.  Set headers to prevent caching.
        response =  render_template('info.html', username=username, email=email, ssn_last_4=ssn_last_4)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        # Handle the case where the user is not found (shouldn't happen if login_required is working)
        abort(404)  # Or redirect to an error page


if __name__ == '__main__':
    from flask import g
    app.run(debug=True)

