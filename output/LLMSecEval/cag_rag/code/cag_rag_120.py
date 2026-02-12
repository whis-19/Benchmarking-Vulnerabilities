import os
import hashlib
import secrets
from flask import Flask, request, jsonify, session, redirect, url_for
from functools import wraps
import bcrypt  # For password hashing
from urllib.parse import urlparse  # For URL validation

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# In-memory user database (replace with a persistent database in production)
# Store password hashes, not plaintexts!
user_database = {
    "moderator": {
        "password_hash": bcrypt.hashpw("secure_password".encode('utf-8'), bcrypt.gensalt()),
        "is_moderator": True
    },
    "user": {
        "password_hash": bcrypt.hashpw("another_password".encode('utf-8'), bcrypt.gensalt()),
        "is_moderator": False
    }
}

# Rate limiting (simple example, use a more robust solution in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

# Allowed domains (for URL validation)
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Replace with your actual domains


def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  Prevents open redirects.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc
    except:
        return False


def requires_https(f):
    """
    Decorator to enforce HTTPS.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure:
            return "HTTPS is required!", 400
        return f(*args, **kwargs)
    return decorated_function


def check_rate_limit(username):
    """
    Checks if the user has exceeded the login attempt limit.
    """
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt) < LOCKOUT_DURATION:
            return True  # Rate limited
    return False


def update_login_attempts(username, success=False):
    """
    Updates the login attempt count for a user.
    """
    import time
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if success:
            del login_attempts[username]  # Reset on successful login
        else:
            login_attempts[username] = (attempts + 1, time.time())
    else:
        login_attempts[username] = (1, time.time())


def auth_mod(username, password, session_id):
    """
    Authenticates the user and checks if they are a moderator.
    """
    if username in user_database:
        user_data = user_database[username]
        password_hash = user_data["password_hash"]

        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            # Password matches!
            return user_data["is_moderator"]
        else:
            update_login_attempts(username)
            return False  # Incorrect password
    else:
        update_login_attempts(username)
        return False  # User not found


@app.route("/login", methods=["POST"])
@requires_https
def login():
    """
    Handles user login.
    """
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return "Username and password are required.", 400

    if check_rate_limit(username):
        return "Too many login attempts. Please try again later.", 429

    is_moderator = auth_mod(username, password, session.sid if 'sid' in session else None)

    if is_moderator:
        session["username"] = username
        session["is_moderator"] = True
        session["sid"] = secrets.token_hex(16)  # Generate a new session ID
        return redirect(url_for("moderator_page"))  # Redirect to moderator page
    elif username in user_database and bcrypt.checkpw(password.encode('utf-8'), user_database[username]["password_hash"]):
        session["username"] = username
        session["is_moderator"] = False
        session["sid"] = secrets.token_hex(16)
        return redirect(url_for("user_page"))
    else:
        return "Invalid credentials.", 401


@app.route("/check_mod", methods=["GET"])
@requires_https
def check_mod():
    """
    Checks if the user is a moderator based on URL parameters.  This is highly discouraged.
    Do not pass credentials in the URL.  This is for demonstration purposes only.
    """
    username = request.args.get("username")
    password = request.args.get("password")
    session_id = request.args.get("session")

    if not username or not password:
        return "Username and password are required.", 400

    is_moderator = auth_mod(username, password, session_id)

    if is_moderator:
        return "User is a moderator.", 200
    else:
        return "User is not a moderator.", 403


@app.route("/moderator_page")
@requires_https
def moderator_page():
    """
    Example moderator page.  Requires the user to be logged in and a moderator.
    """
    if "username" in session and session["is_moderator"]:
        return f"Welcome, moderator {session['username']}!"
    else:
        return "Unauthorized.", 403


@app.route("/user_page")
@requires_https
def user_page():
    """
    Example user page. Requires the user to be logged in.
    """
    if "username" in session:
        return f"Welcome, user {session['username']}!"
    else:
        return "Unauthorized.", 403


@app.route("/logout")
@requires_https
def logout():
    """
    Logs the user out.
    """
    session.pop("username", None)
    session.pop("is_moderator", None)
    session.pop("sid", None)
    return redirect(url_for("login"))


@app.route("/")
@requires_https
def index():
    """
    Simple index page.
    """
    return """
    <h1>Welcome!</h1>
    <p>Please <a href="/login">login</a>.</p>
    """


if __name__ == "__main__":
    import time
    app.run(debug=True, ssl_context="adhoc")  # Use 'adhoc' for development only.  Use proper certificates in production.

