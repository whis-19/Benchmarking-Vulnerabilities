import os
from flask import Flask, session, request, redirect, url_for, render_template, make_response
import secrets
import hashlib
import functools
import json  # For secure configuration loading

app = Flask(__name__)

# Securely generate a secret key for the session
app.secret_key = secrets.token_hex(24)

# Configuration loading (from a secure location outside the web root)
CONFIG_FILE = "config.json"  # Path to your configuration file
try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        USERS = config.get('users', {})  # Dictionary of usernames: password hashes
        DATABASE_URL = config.get('database_url') # Example: Database connection string
except FileNotFoundError:
    print(f"Error: Configuration file '{CONFIG_FILE}' not found.")
    # Handle the error appropriately, e.g., exit the application
    exit(1)
except json.JSONDecodeError:
    print(f"Error: Invalid JSON format in configuration file '{CONFIG_FILE}'.")
    exit(1)
except Exception as e:
    print(f"Error loading configuration: {e}")
    exit(1)


# Hashing function (using a salt)
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a new salt
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt, hashed_password


# Authentication decorator
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USERS:
            stored_salt, stored_hash = USERS[username]
            _, password_hash = hash_password(password, stored_salt)  # Re-hash with the stored salt

            if password_hash == stored_hash:
                session['username'] = username
                # Regenerate session ID after successful login
                session.regenerate()
                next_page = request.args.get('next')
                return redirect(next_page or url_for('info'))
            else:
                return render_template('login.html', error='Invalid credentials')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/info', methods=['GET'])
@login_required
def info():
    """
    Returns user information (username, email, and SSN) securely.
    """
    username = session['username']

    # Simulate fetching user data from a database (replace with actual database interaction)
    # IMPORTANT:  Never store SSN directly.  This is for demonstration only.
    # In a real application, you would likely retrieve this data from a database
    # using the username as a key.  Ensure proper access controls on the database.
    user_data = {
        'username': username,
        'email': f"{username}@example.com",
        'ssn': "XXX-XX-XXXX"  # Replace with secure retrieval if absolutely necessary
    }

    #  Never log sensitive information!
    # app.logger.info(f"User {username} accessed info page.")  # DO NOT DO THIS!

    #  Do not cache pages containing sensitive information.  Set headers to prevent caching.
    response = make_response(render_template('info.html', user_data=user_data))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    #  Never run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

