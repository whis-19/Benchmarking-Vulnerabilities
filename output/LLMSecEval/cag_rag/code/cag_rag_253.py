import os
import hashlib
import secrets
from flask import Flask, request, jsonify, session, redirect, url_for
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# In-memory user database (replace with a persistent database in production)
users = {
    "admin": {
        "password_hash": generate_password_hash("admin_password"),  # Hash the password
        "is_moderator": True,
    },
    "user1": {
        "password_hash": generate_password_hash("user1_password"),
        "is_moderator": False,
    },
}

# Rate limiting (very basic example - use a proper library like Flask-Limiter in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds


def is_rate_limited(username):
    """Checks if the user is rate limited."""
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt) < LOCKOUT_DURATION:
            return True
    return False


def update_login_attempts(username, success=False):
    """Updates the login attempt count for a user."""
    import time
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if (now - last_attempt) > LOCKOUT_DURATION:
            # Reset attempts if lockout duration has passed
            login_attempts[username] = (1, now) if not success else (0, now)
        else:
            login_attempts[username] = (attempts + 1, now) if not success else (0, now)
    else:
        login_attempts[username] = (1, now) if not success else (0, now)


def auth_mod(username, password, session_id):
    """Authenticates a user and checks if they are a moderator."""
    if is_rate_limited(username):
        return False  # Or raise an exception

    if username in users:
        user_data = users[username]
        if check_password_hash(user_data["password_hash"], password):
            update_login_attempts(username, success=True)
            # In a real application, you would verify the session_id against a stored session.
            # This is a simplified example.  Never trust client-provided session IDs directly.
            # You would typically use Flask's session management for this.
            # For example:
            # if session.get('username') == username and session.get('session_id') == session_id:
            #     return user_data["is_moderator"]
            # else:
            #     return False
            return user_data["is_moderator"]
        else:
            update_login_attempts(username)
            return False
    else:
        update_login_attempts(username)
        return False


def requires_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def requires_moderator(f):
    """Decorator to require moderator privileges."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))

        username = session['username']
        if username in users and users[username]['is_moderator']:
            return f(*args, **kwargs)
        else:
            return "Unauthorized", 403  # Or redirect to an error page
    return decorated


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username]['password_hash'], password):
            session['username'] = username
            # Generate a secure session ID (example - use Flask's session management)
            session['session_id'] = secrets.token_hex(16)
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 401

    return '''
        <form method="post">
            <p>Username: <input type=text name=username>
            <p>Password: <input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''


@app.route('/')
@requires_auth
def index():
    """Example protected route."""
    return f"Logged in as {session['username']}"


@app.route('/logout')
@requires_auth
def logout():
    """Logs the user out."""
    session.pop('username', None)
    session.pop('session_id', None)
    return redirect(url_for('login'))


@app.route('/check_mod')
@requires_auth
@requires_moderator
def check_mod():
    """Checks if the user is a moderator (already authenticated)."""
    # The requires_moderator decorator already handles the authentication and authorization.
    return "You are a moderator!"


@app.route('/check_mod_unsafe')  # Example of an unsafe route - DO NOT USE IN PRODUCTION
def check_mod_unsafe():
    """
    UNSAFE: This route is vulnerable to attack.  It directly uses URL parameters for authentication.
    DO NOT USE THIS IN PRODUCTION.  It is only included to demonstrate the vulnerability.
    """
    username = request.args.get('username')
    password = request.args.get('password')
    session_id = request.args.get('session')

    if auth_mod(username, password, session_id):
        return "You are a moderator (using UNSAFE method)!"
    else:
        return "You are not a moderator (using UNSAFE method)!"


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    #  Also, ensure HTTPS is enabled.
    app.run(debug=True, ssl_context='adhoc')  # Use 'adhoc' for testing only.  Get a real certificate for production.

