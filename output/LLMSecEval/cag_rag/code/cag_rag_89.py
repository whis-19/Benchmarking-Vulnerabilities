from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_wtf.csrf import CSRFProtect
import os
import secrets
import hashlib
import hmac
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

app = Flask(__name__)

# Security: Generate a strong, random secret key for the Flask app
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Security: Enable CSRF protection
csrf = CSRFProtect(app)

# In-memory user database (replace with a real database in production)
users = {}

# Allowed domains for redirects (add your domains here)
ALLOWED_DOMAINS = ['localhost', '127.0.0.1']  # Example: ['example.com', 'www.example.com']

# --- Authentication and Authorization ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('register.html', error='Username and password are required.')

        if username in users:
            return render_template('register.html', error='Username already exists.')

        # Security: Hash the password before storing it
        hashed_password = generate_password_hash(password)
        users[username] = hashed_password

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error='Username and password are required.')

        if username not in users:
            return render_template('login.html', error='Invalid username or password.')

        # Security: Verify the password against the stored hash
        if check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('protected'))
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html', username=session['username'])


# --- Main Application Logic ---

@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    if request.method == 'POST':
        try:
            payload = request.get_json()  # Get JSON payload from the request

            if not isinstance(payload, dict):
                return jsonify({'error': 'Invalid JSON payload'}), 400

            if 'name' in payload:
                # Security: Escape the user input before rendering it in HTML
                name = escape(payload['name'])
                return jsonify({'name': name})
            else:
                return jsonify({'message': 'Field "name" not found in payload'}), 400

        except Exception as e:
            print(f"Error processing request: {e}") # Log the error for debugging
            return jsonify({'error': 'Invalid request'}), 400

    # Security:  Set Content Security Policy (CSP) to mitigate XSS attacks
    csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return render_template('index.html', csp=csp)


# --- Utility Functions ---

def escape(data):
    """
    Security: Escape HTML characters to prevent XSS attacks.
    """
    if isinstance(data, str):
        return data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    return data


def is_safe_redirect_url(target):
    """
    Security: Validate redirect URLs to prevent open redirects.
    """
    if not target:
        return False

    try:
        parsed_url = urlparse(target)
        # Check if the scheme is safe (e.g., http or https)
        if parsed_url.scheme and parsed_url.scheme not in ('http', 'https'):
            return False

        # Check if the hostname is in the allowed list
        if parsed_url.netloc and parsed_url.netloc not in ALLOWED_DOMAINS:
            return False

        return True
    except Exception:
        return False


@app.route('/redirect')
def redirect_route():
    """
    Security: Example of a safe redirect.  Always validate the target URL.
    """
    target = request.args.get('next')

    if is_safe_redirect_url(target):
        return redirect(target)
    else:
        return "Invalid redirect URL", 400


# --- Error Handling ---

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404


@app.errorhandler(500)
def internal_server_error(e):
    return "Internal server error", 500


if __name__ == '__main__':
    # Security:  Don't use debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)

