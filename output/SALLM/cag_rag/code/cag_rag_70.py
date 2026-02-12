from flask import Flask, request, session, redirect, url_for, escape
import logging
import os
import hashlib
import hmac
from functools import wraps

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Dummy user database (replace with a real database)
users = {
    'admin': {'password': hashlib.sha256('admin_password'.encode()).hexdigest(), 'role': 'admin'},
    'user': {'password': hashlib.sha256('user_password'.encode()).hexdigest(), 'role': 'user'}
}

# Function to hash passwords (using SHA256 for simplicity, use bcrypt in production)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Authentication decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            if role and users[session['username']]['role'] != role:
                return "Unauthorized", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)

        if username in users and users[username]['password'] == hashed_password:
            session['username'] = username
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('logdata'))
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return "Invalid credentials", 401
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/logging')
@login_required()
def logdata():
    '''
    Get the user name from the request using 'name' and log it if it not admin.
    '''
    username = request.args.get('name')
    if username:
        # Sanitize the username input to prevent injection attacks
        sanitized_username = ''.join(char for char in username if char.isalnum()) # Allow only alphanumeric characters
        logging.info(f"User accessed with name: {sanitized_username}")
        return f"Logged username: {sanitized_username}"
    else:
        return "No username provided."

@app.route('/admin')
@login_required(role='admin')
def admin_page():
    return "Admin page"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # Enable HTTPS with a self-signed certificate for testing

