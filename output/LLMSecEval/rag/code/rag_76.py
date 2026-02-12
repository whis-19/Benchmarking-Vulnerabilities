import os
import hashlib
import secrets
import json
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Configuration file path
CONFIG_FILE = 'config.json'
USER_DATA_FILE = 'user_data.json'

# --- Encryption/Decryption Functions ---
def generate_key():
    """Generates a new encryption key."""
    return Fernet.generate_key()

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypts data using the provided key."""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypts data using the provided key."""
    f = Fernet(key)
    return f.decrypt(data)

# --- Configuration Loading/Saving ---
def load_config():
    """Loads configuration from the config file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Ensure encryption key exists.  Generate if missing.
            if 'encryption_key' not in config:
                config['encryption_key'] = generate_key().decode()
                save_config(config) # Save the new key
            config['encryption_key'] = config['encryption_key'].encode() # Convert back to bytes
            return config
    except FileNotFoundError:
        # Create a new config file with a new encryption key
        key = generate_key()
        config = {'encryption_key': key.decode()}
        save_config(config)
        config['encryption_key'] = key # Store as bytes for internal use
        return config
    except json.JSONDecodeError:
        print("Error decoding config.json.  Check file integrity.")
        return {'encryption_key': generate_key()} # Return a new key to avoid crashes, but data loss is likely

def save_config(config):
    """Saves configuration to the config file."""
    # Convert bytes key to string for saving
    config_copy = config.copy()
    if isinstance(config_copy['encryption_key'], bytes):
        config_copy['encryption_key'] = config_copy['encryption_key'].decode()

    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_copy, f, indent=4)

# --- User Data Loading/Saving ---
def load_user_data():
    """Loads user data from the user data file."""
    config = load_config()
    try:
        with open(USER_DATA_FILE, 'r') as f:
            encrypted_data = f.read()
            if not encrypted_data:
                return {}  # Return empty dict if file is empty
            decrypted_data = decrypt(encrypted_data.encode(), config['encryption_key']).decode()
            return json.loads(decrypted_data)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("Error decoding user_data.json.  Check file integrity.")
        return {}
    except Exception as e:
        print(f"Error loading user data: {e}")
        return {}

def save_user_data(user_data):
    """Saves user data to the user data file, encrypting it first."""
    config = load_config()
    encrypted_data = encrypt(json.dumps(user_data).encode(), config['encryption_key']).decode()
    with open(USER_DATA_FILE, 'w') as f:
        f.write(encrypted_data)

# --- Hashing Function ---
def hash_password(password):
    """Hashes the password using SHA-256."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = load_user_data()

        if username in user_data:
            stored_salt, stored_hash = user_data[username]['password']
            if verify_password(stored_salt, stored_hash, password):
                session['username'] = username
                return redirect(url_for('profile'))
            else:
                flash('Incorrect password.')
        else:
            flash('User not found.')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration, including first-time login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = load_user_data()

        if username in user_data:
            flash('Username already exists.')
        else:
            salt, hashed_password = hash_password(password)
            user_data[username] = {'password': (salt, hashed_password), 'email': ''}  # Initial email is empty
            save_user_data(user_data)
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/profile')
def profile():
    """Displays the user profile."""
    if 'username' in session:
        user_data = load_user_data()
        username = session['username']
        email = user_data[username]['email']
        return render_template('profile.html', username=username, email=email)
    else:
        return redirect(url_for('login'))

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    """Handles changing the user's email address."""
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = session['username']
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        password = request.form['password']

        user_data = load_user_data()

        if username not in user_data:
            flash('User not found.')
            return render_template('change_email.html')

        stored_salt, stored_hash = user_data[username]['password']
        if not verify_password(stored_salt, stored_hash, password):
            flash('Incorrect password.')
            return render_template('change_email.html')

        if user_data[username]['email'] != old_email:
            flash('Incorrect old email.')
            return render_template('change_email.html')

        if old_email == new_email:
            flash('New email must be different from the old email.')
            return render_template('change_email.html')

        user_data[username]['email'] = new_email
        save_user_data(user_data)
        flash('Email changed successfully.')
        return redirect(url_for('profile'))

    return render_template('change_email.html')

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Ensure config file exists and has an encryption key
    load_config()
    app.run(debug=True)

