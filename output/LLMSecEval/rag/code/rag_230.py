import os
import hashlib
import secrets
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, g
from cryptography.fernet import Fernet
import logging

# Initialize Flask application
app = Flask(__name__)
app.config['DATABASE'] = 'users.db'  # Database file
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Session secret key

# Configure logging (important for security audits, but avoid logging sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Encryption Key Management ---
#  Ideally, the encryption key should be stored securely,
#  e.g., using a dedicated key management system (KMS) or hardware security module (HSM).
#  For this example, we'll generate and store it in a file, but this is NOT suitable for production.

KEY_FILE = 'encryption.key'

def generate_encryption_key():
    """Generates a new Fernet encryption key and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

def load_encryption_key():
    """Loads the encryption key from the file."""
    try:
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        logging.warning("Encryption key file not found. Generating a new one.  THIS IS NOT RECOMMENDED FOR PRODUCTION.")
        return generate_encryption_key()  # Generate if missing (NOT production-safe)

encryption_key = load_encryption_key()
fernet = Fernet(encryption_key)


# --- Database Connection ---
def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        g.sqlite_db.row_factory = sqlite3.Row  # Access columns by name
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def init_db():
    """Initializes the database schema."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')


# --- Password Hashing ---
def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash


# --- User Registration ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error='Username and password are required.')

        db = get_db()
        try:
            # Hash the password
            salt, hashed_password = hash_password(password)

            # Encrypt the username before storing it
            encrypted_username = fernet.encrypt(username.encode()).decode()

            # Insert the user into the database
            db.execute("INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)",
                       (encrypted_username, salt, hashed_password))
            db.commit()

            logging.info(f"User registered: {username}") # Log the registration event (username is OK here as it's an event log)

            return redirect(url_for('login'))  # Redirect to login page after successful registration

        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists.')
        except Exception as e:
            logging.error(f"Registration error: {e}") # Log the error
            return render_template('register.html', error='An error occurred during registration.')

    return render_template('register.html')


# --- User Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('login.html', error='Username and password are required.')

        db = get_db()
        try:
            # Encrypt the username for database lookup
            encrypted_username = fernet.encrypt(username.encode()).decode()

            # Retrieve the user from the database
            cur = db.execute("SELECT username, password_salt, password_hash FROM users WHERE username = ?", (encrypted_username,))
            user = cur.fetchone()
            cur.close()

            if user:
                # Verify the password
                if verify_password(user['password_salt'], user['password_hash'], password):
                    # Password is correct
                    logging.info(f"User logged in: {username}") # Log the login event (username is OK here as it's an event log)
                    return render_template('success.html', username=username) # Replace with proper session management

                else:
                    return render_template('login.html', error='Incorrect password.')
            else:
                return render_template('login.html', error='User not found.')

        except Exception as e:
            logging.error(f"Login error: {e}") # Log the error
            return render_template('login.html', error='An error occurred during login.')

    return render_template('login.html')


@app.route('/')
def index():
    return "Hello, world!  Try /register or /login"


if __name__ == '__main__':
    # Ensure the database file exists and is initialized
    if not os.path.exists(app.config['DATABASE']):
        with app.app_context():
            init_db()

    app.run(debug=True)  # Disable debug mode in production!

