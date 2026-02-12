import os
import hashlib
import secrets
import configparser
from flask import Flask, render_template, request, session, redirect, url_for, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Configuration file path
CONFIG_FILE = 'config.ini'

def create_config_file():
    """Creates the configuration file if it doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config['DEFAULT'] = {
            'first_login': 'True'  # Flag for first-time login
        }
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)

def get_config():
    """Reads the configuration file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config

def save_config(config):
    """Saves the configuration to the file."""
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def hash_password(password, salt=None):
    """Hashes the password using pbkdf2_hmac with a salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Use a strong hashing algorithm like pbkdf2_hmac
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt.encode('utf-8'),  # Provide the salt
        100000  # Number of iterations
    )
    return salt, hashed_password.hex()

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salt, hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash

@app.route('/', methods=['GET', 'POST'])
def login():
    create_config_file()  # Ensure the config file exists
    config = get_config()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if config['DEFAULT'].getboolean('first_login'):
            # First-time login: set username and password
            salt, hashed_password = hash_password(password)
            config['DEFAULT']['first_login'] = 'False'
            config['DEFAULT']['username'] = username
            config['DEFAULT']['password_salt'] = salt
            config['DEFAULT']['password_hash'] = hashed_password
            save_config(config)
            session['username'] = username
            return redirect(url_for('session_page'))
        else:
            # Regular login
            stored_username = config['DEFAULT']['username']
            stored_salt = config['DEFAULT']['password_salt']
            stored_hash = config['DEFAULT']['password_hash']

            if username == stored_username and verify_password(stored_salt, stored_hash, password):
                session['username'] = username
                return redirect(url_for('session_page'))
            else:
                return render_template('login.html', error='Incorrect username or password')

    return render_template('login.html', first_login=config['DEFAULT'].getboolean('first_login'))

@app.route('/session')
def session_page():
    if 'username' in session:
        return render_template('session.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    # Ensure the config file has restricted access (Linux/macOS)
    if os.name != 'nt':  # Not Windows
        os.chmod(CONFIG_FILE, 0o600)  # Owner read/write only

    app.run(debug=False, host='0.0.0.0', port=5000)

