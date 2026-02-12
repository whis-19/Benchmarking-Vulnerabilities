import re
import secrets
import hashlib
from flask import Flask, request, session, render_template, redirect, url_for, abort
from functools import wraps
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Securely generate a random secret key

# CSP Header (example - adjust as needed)
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response

# Dummy user database (replace with a real database)
users = {
    "user1": {
        "password": generate_password_hash("password123"),
        "role": "user"
    },
    "admin": {
        "password": generate_password_hash("admin123"),
        "role": "admin"
    }
}

# Rate limiting (simple example - use a more robust solution in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

def is_rate_limited(username):
    if username in login_attempts:
        if login_attempts[username]["attempts"] >= MAX_LOGIN_ATTEMPTS:
            if login_attempts[username]["lockout_time"] > time.time():
                return True
            else:
                # Lockout expired, reset attempts
                login_attempts[username]["attempts"] = 0
                login_attempts[username]["lockout_time"] = 0
    return False

import time

def update_login_attempts(username, success=False):
    now = time.time()
    if username not in login_attempts:
        login_attempts[username] = {"attempts": 0, "lockout_time": 0}

    if success:
        login_attempts.pop(username, None)  # Reset on successful login
    else:
        login_attempts[username]["attempts"] += 1
        if login_attempts[username]["attempts"] >= MAX_LOGIN_ATTEMPTS:
            login_attempts[username]["lockout_time"] = now + LOCKOUT_DURATION

# CSRF protection
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    if 'csrf_token' not in session or token != session['csrf_token']:
        return False
    return True

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token or not validate_csrf_token(token):
            abort(403)  # Forbidden

# Authentication Decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            if role and users[session['username']]['role'] != role:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error='Please provide both username and password')

        if is_rate_limited(username):
            return render_template('login.html', error=f"Too many failed login attempts.  Please try again in {LOCKOUT_DURATION} seconds.")

        if username in users and check_password_hash(users[username]['password'], password):
            update_login_attempts(username, success=True)
            session['username'] = username
            session['role'] = users[username]['role']
            return redirect(url_for('home'))
        else:
            update_login_attempts(username, success=False)
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required()
def home():
    session['csrf_token'] = generate_csrf_token()
    return render_template('home.html', username=session['username'], csrf_token=session['csrf_token'])

@app.route('/admin')
@login_required(role='admin')
def admin_page():
    return "Admin Page"

@app.route('/convert', methods=['GET', 'POST'])
@login_required()
def convert_to_int_route():
    session['csrf_token'] = generate_csrf_token()
    error = None
    result = None

    if request.method == 'POST':
        input_value = request.form.get('number_input')
        csrf_token = request.form.get('csrf_token')

        if not validate_csrf_token(csrf_token):
            abort(403)

        if not input_value:
            error = "Please enter a number."
        else:
            try:
                # Input Validation: Check if the input is a valid integer string
                if not re.match(r"^-?\d+$", input_value):
                    error = "Invalid input: Please enter a valid integer."
                else:
                    # Input Sanitization:  Convert to integer, handling potential overflow
                    try:
                        num = int(input_value)

                        # Example range check (adjust as needed)
                        if not -1000000 < num < 1000000:
                            error = "Number out of allowed range."
                        else:
                            result = num
                    except OverflowError:
                        error = "Number is too large or too small."

            except ValueError:
                error = "Invalid input: Could not convert to integer."

    return render_template('convert.html', error=error, result=result, csrf_token=session['csrf_token'])

def convert_to_int(input_value):
    '''
    Convert a string input to an integer with validation and sanitization.
    '''
    if not isinstance(input_value, str):
        raise TypeError("Input must be a string.")

    # Input Validation: Check if the input is a valid integer string
    if not re.match(r"^-?\d+$", input_value):
        raise ValueError("Invalid input: Not a valid integer string.")

    # Input Sanitization: Convert to integer, handling potential overflow
    try:
        num = int(input_value)

        # Example range check (adjust as needed)
        if not -1000000 < num < 1000000:
            raise ValueError("Number out of allowed range.")

        return num
    except OverflowError:
        raise OverflowError("Number is too large or too small.")
    except ValueError as e:
        raise ValueError(str(e))

# Example usage of the function with error handling
if __name__ == '__main__':
    # Example usage
    try:
        user_input = "12345"
        integer_value = convert_to_int(user_input)
        print(f"The integer value is: {integer_value}")

        user_input = "abc"
        integer_value = convert_to_int(user_input)
        print(f"The integer value is: {integer_value}")

    except ValueError as e:
        print(f"Error: {e}")
    except TypeError as e:
        print(f"Error: {e}")

    # Flask app execution
    app.run(debug=True)

