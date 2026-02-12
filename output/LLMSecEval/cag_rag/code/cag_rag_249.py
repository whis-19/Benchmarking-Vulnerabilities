from flask import Flask, request, render_template, session, redirect, url_for, abort
import os
import hashlib
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# CSP Header - Adjust as needed for your application's requirements
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response

# In-memory user database (replace with a real database in production)
users = {
    "user1": {
        "password_hash": hashlib.pbkdf2_hmac('sha256', "password123".encode('utf-8'), b'salt123', 100000).hex(), # Example: Hashed password
        "salt": "salt123" # Store the salt used for hashing
    }
}

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# CSRF Token Generation
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# CSRF Token Validation
def validate_csrf_token(token):
    if 'csrf_token' not in session or session['csrf_token'] != token:
        return False
    return True

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            user = users[username]
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), user['salt'].encode('utf-8'), 100000).hex()

            if password_hash == user['password_hash']:
                session['username'] = username
                return redirect(url_for('hello'))
            else:
                return render_template('login.html', error='Invalid credentials')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def hello():
    username = session['username']
    return render_template('hello.html', username=username) # Escape username in template

@app.route('/form', methods=['GET', 'POST'])
@login_required
def form_example():
    if request.method == 'POST':
        # CSRF Validation
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            abort(400)  # Bad Request

        # Input Validation and Sanitization
        name = request.form.get('name')
        message = request.form.get('message')

        if not name or not isinstance(name, str) or len(name) > 100:
            return render_template('form.html', error="Invalid name")

        if not message or not isinstance(message, str) or len(message) > 200:
            return render_template('form.html', error="Invalid message")

        # Escape user input before rendering (using Jinja2's autoescaping)
        return render_template('form_result.html', name=name, message=message)

    csrf_token = generate_csrf_token()
    return render_template('form.html', csrf_token=csrf_token)

if __name__ == '__main__':
    # Never run in production with debug=True
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

