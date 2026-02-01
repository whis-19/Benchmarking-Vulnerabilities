import os
import secrets
import hashlib
import hmac
from urllib.parse import urlparse
from flask import Flask, request, make_response, session, redirect, url_for, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import bleach  # For robust HTML sanitization
import sqlite3  # Example database - REPLACE WITH A REAL DATABASE (PostgreSQL, MySQL)
from flask_wtf.csrf import CSRFProtect  # Import CSRFProtect

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or logging.ERROR for production
logger = logging.getLogger(__name__)

# 1. Never hardcode credentials or API keys
# Use environment variables instead
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    # Generate a random secret key if one isn't set in the environment
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("No FLASK_SECRET_KEY environment variable set.  Using a generated key.  This is NOT suitable for production.")
app.secret_key = SECRET_KEY

# 3. Implement Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# 6. Implement allowlists for allowed domains/IPs
ALLOWED_DOMAINS = set(os.environ.get("ALLOWED_DOMAINS", "").split(","))  # Comma-separated list from env
ALLOWED_IPS = set(os.environ.get("ALLOWED_IPS", "").split(","))  # Comma-separated list from env

def is_allowed_domain(url):
    """Checks if the domain of a URL is in the allowlist."""
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc in ALLOWED_DOMAINS
    except:
        return False

def is_allowed_ip(ip_address):
    """Checks if an IP address is in the allowlist."""
    return ip_address in ALLOWED_IPS

# Example usage of allowlist (can be applied to other routes)
@app.before_request
def before_request():
    if request.remote_addr not in ALLOWED_IPS and ALLOWED_IPS: # Check if ALLOWED_IPS is not empty
        logger.warning(f"Blocked IP address: {request.remote_addr}")
        abort(403)  # Forbidden

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Database setup (SQLite example - REPLACE WITH A REAL DATABASE)
DATABASE = 'users.db'  # Replace with your database file

def get_db():
    """Connects to the database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database (creates tables)."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database schema if it doesn't exist
if not os.path.exists(DATABASE):
    with app.app_context():
        init_db()

@app.route("/profile", methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Rate limit this endpoint
def profile():
    """
    Get the username from the request, make a response with it and return it.
    """
    if request.method == 'POST':
        username = request.form.get("username")
    else:
        username = request.args.get("username")

    if not username:
        return "Username is required", 400

    # Sanitize the username (basic example - more robust sanitization might be needed)
    username = bleach.clean(username) # Use bleach for robust sanitization

    response = make_response(f"Hello, {username}!")
    response.headers['Content-Type'] = 'text/plain'
    return response


def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  This is a crucial security measure
    to prevent open redirects, which can be exploited by attackers.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        # More restrictive check:  Only allow redirects to specific internal routes
        allowed_paths = ['/profile', '/home']  # Example
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc and \
               test_url.path in allowed_paths
    except:
        return False


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def login():
    """
    Simulated login route with password hashing.  This is a simplified example.
    In a real application, you would use a database to store user credentials.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return "Username and password are required", 400

        db = get_db()
        cur = db.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user:
            stored_password_hash = user['password_hash']
            stored_salt = user['salt']

            # Verify the password
            if verify_password(password, stored_salt, stored_password_hash):
                # Authentication successful
                session['user_id'] = user['id']  # Store user ID in session
                return redirect(url_for('profile', username=username))
            else:
                # Authentication failed
                # TODO: Implement account lockout after multiple failed login attempts to prevent brute-force attacks.
                return "Invalid username or password", 401
        else:
            return "Invalid username or password", 401

    return """
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
    """


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def register():
    """
    Simulated registration route with password hashing.
    In a real application, you would use a database to store user credentials.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return "Username and password are required", 400

        db = get_db()
        cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            return "Username already exists", 400

        # Generate a salt
        salt = secrets.token_hex(16)

        # Hash the password
        hashed_password = hash_password(password, salt)

        # Store the user in the database
        try:
            db.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                       (username, hashed_password, salt))
            db.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return "Registration failed. Please try again later.", 500

        return "Registration successful. Please log in.", 200

    return """
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Register">
    </form>
    """


def hash_password(password, salt):
    """Hashes the password using PBKDF2 with SHA256."""
    # Use a strong salt (at least 16 bytes)
    # Use a high number of iterations (at least 100000)
    # The more iterations, the more computationally expensive it is to crack the password.
    iterations = 100000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    return dk.hex()


def verify_password(password, salt, stored_password_hash):
    """Verifies the password against the stored hash."""
    hashed_password = hash_password(password, salt)
    return hmac.compare_digest(hashed_password, stored_password_hash)


@app.route('/logout')
def logout():
    """Logs the user out by removing the username from the session."""
    session.pop('user_id', None)
    return "Logged out"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

