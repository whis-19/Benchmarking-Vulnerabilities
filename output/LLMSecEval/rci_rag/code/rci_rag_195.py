import hashlib
import os
import secrets
import json
from flask import Flask, render_template, request, redirect, url_for, session, abort
import logging  # Import the logging module

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration file path
CONFIG_FILE = os.path.abspath('config.json')  # Use an absolute path

# Session Cookie Configuration (Production)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (Lax or Strict)


def load_config():
    """Loads configuration from the config file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.warning(f"Config file not found: {CONFIG_FILE}")  # Log the event
        return {}  # Return an empty dictionary if the file doesn't exist
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding config.json: {e}")
        return {}
    except Exception as e:
        logging.exception(f"Error loading config.json: {e}") # Log the full exception
        return {}


def save_config(config):
    """Saves configuration to the config file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True  # Indicate success
    except IOError as e:
        logging.error(f"Error writing to config.json: {e}")
        return False  # Indicate failure to save
    except Exception as e:
        logging.exception(f"Unexpected error writing to config.json: {e}")
        return False


def hash_password(password, salt=None, iterations=100000):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt

    # Use a strong hashing algorithm like PBKDF2-HMAC
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password.encode('utf-8'),  # Convert password to bytes
        salt.encode('utf-8'),  # Convert salt to bytes
        iterations  # Number of iterations (adjust as needed) - Make this configurable!
    )
    return salt, hashed_password.hex()


def verify_password(stored_salt, stored_hash, password, iterations=100000):
    """Verifies the password against the stored hash and salt."""
    salt, hashed_password = hash_password(password, stored_salt, iterations)
    return hashed_password == stored_hash


def create_default_config():
    """Creates a default configuration with a 'first_login' flag."""
    config = {'first_login': True, 'pbkdf2_iterations': 100000}  # Include iterations in config
    if not save_config(config):
        logging.error("Failed to create default configuration.")
        return None
    return config


# Load configuration at startup
config = load_config()
if not config:
    config = create_default_config()
    if config is None:
        logging.critical("Application cannot start without a valid configuration. Exiting.")
        exit()

PBKDF2_ITERATIONS = config.get('pbkdf2_iterations', 100000)  # Load iterations from config


@app.route('/', methods=['GET', 'POST'])
def login():
    """Handles the login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation (Example - more thorough validation is needed)
        if not (isinstance(username, str) and 0 < len(username) <= 50):  # Example length check
            return render_template('login.html', message='Invalid username format.')
        if not (isinstance(password, str) and 0 < len(password) <= 100): # Example length check
            return render_template('login.html', message='Invalid password format.')

        config = load_config()  # Reload config in case it changed
        if not config:
            return render_template('login.html', message='Error loading configuration. Please try again.')

        if config.get('first_login', False):
            # First login mode: require setting a new password
            if username == "admin":  # Or whatever default username you want to use
                # Password Complexity Check
                if len(password) < 8:
                    return render_template('login.html', message='Password must be at least 8 characters long.')
                if not any(char.isdigit() for char in password):
                    return render_template('login.html', message='Password must contain at least one digit.')
                if not any(char.isupper() for char in password):
                    return render_template('login.html', message='Password must contain at least one uppercase letter.')
                if not any(char.islower() for char in password):
                    return render_template('login.html', message='Password must contain at least one lowercase letter.')
                if not any(char in "!@#$%^&*()" for char in password):
                    return render_template('login.html', message='Password must contain at least one special character.')

                salt, hashed_password = hash_password(password, iterations=PBKDF2_ITERATIONS)
                config['users'] = {username: {'salt': salt, 'hash': hashed_password}}
                config['first_login'] = False
                if save_config(config):
                    session['username'] = username
                    return redirect(url_for('session_page'))
                else:
                    return render_template('login.html', message='Error saving configuration. Please try again.')
            else:
                return render_template('login.html', message='Invalid username for first login.')

        else:
            # Regular login
            users = config.get('users', {})
            user_data = users.get(username)

            if user_data and verify_password(user_data['salt'], user_data['hash'], password, iterations=PBKDF2_ITERATIONS):
                session['username'] = username
                return redirect(url_for('session_page'))
            else:
                return render_template('login.html', message='Incorrect username or password.')

    return render_template('login.html', message=None)


@app.route('/session')
def session_page():
    """Displays the session page after successful login."""
    if 'username' in session:
        return render_template('session.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(error):
    """Handles 404 errors."""
    return render_template('404.html'), 404


if __name__ == '__main__':
    # Ensure the config file exists and has proper permissions
    if not os.path.exists(CONFIG_FILE):
        config = create_default_config()
        if config is None:
            logging.critical("Failed to create default configuration. Exiting.")
            exit()
    try:
        os.chmod(CONFIG_FILE, 0o600)  # Restrict access to the owner (read/write)
    except OSError as e:
        logging.error(f"Error setting file permissions on config.json: {e}")
        # Consider if the application should continue if permissions cannot be set.
        # In a production environment, this might be a fatal error.

    app.run(debug=False, host='0.0.0.0', port=5000)

