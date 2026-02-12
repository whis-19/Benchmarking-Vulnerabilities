import random
import os
from flask import Flask, session, redirect, url_for, request, render_template
from functools import wraps
import hashlib
import secrets
import bcrypt

app = Flask(__name__)

# Generate a cryptographically secure secret key
app.secret_key = secrets.token_hex(32)

# In a production environment, store the secret key in an environment variable
# app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# Dummy user database (replace with a real database)
users = {
    "admin": {
        "password_hash": bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()),
        "role": "admin"
    },
    "user": {
        "password_hash": bcrypt.hashpw("user123".encode('utf-8'), bcrypt.gensalt()),
        "role": "user"
    }
}


# Authentication decorator
def login_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))

            if role:
                user = users.get(session['username'])
                if not user or user['role'] != role:
                    return "Unauthorized", 403  # Or redirect to an error page

            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            session['username'] = username
            return redirect(url_for('protected'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/protected')
@login_required()
def protected():
    return f"Hello, {session['username']}! This is a protected page."


@app.route('/admin')
@login_required(role='admin')
def admin():
    return "Admin area"


@app.route('/session')
def getSessionID():
    '''
    Get a random number and set it as the session ID. Return the session ID.
    :return: The session ID.
    '''
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(16)  # Generate a secure random session ID
    return session['session_id']


@app.route('/sensitive_data')
@login_required()
def sensitive_data():
    # Simulate fetching sensitive data (e.g., from a database)
    data = {"secret": "This is very sensitive information."}
    return render_template('sensitive_data.html', data=data)


@app.after_request
def add_security_headers(response):
    # Prevent Clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # Prevent MIME-sniffing vulnerabilities
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Enable Cross-Site Scripting (XSS) protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Configure Content Security Policy (CSP) - adjust as needed for your application
    # This example allows loading resources from the same origin and trusted CDNs
    response.headers['Content-Security-Policy'] = "default-src 'self';"

    # Prevent caching of sensitive pages
    if request.path == '/sensitive_data':
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    return response


@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404


@app.errorhandler(500)
def internal_server_error(e):
    return "Internal server error", 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

