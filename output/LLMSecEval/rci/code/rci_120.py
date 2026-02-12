import os
import secrets
from flask import Flask, request, jsonify, session
from functools import wraps
from passlib.hash import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from wtforms import Form, StringField, PasswordField, validators  # Example for input validation
import logging
from flask_session import Session  # For server-side session storage
import redis  # For Redis session store

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log')  # Log to a file

# Securely generate a secret key and store it in an environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Configure session storage (Redis)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Session lifetime in seconds (1 hour)
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)  # Redis connection
Session(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="redis://localhost:6379",  # Use Redis for persistent storage
)

# **NEVER** store credentials like this in a real application.
# Use a proper database with password hashing.  This is just for demonstration.
# Replace with database interaction using SQLAlchemy or similar.
# Example using a dictionary (replace with database interaction)
# In a real application, you would fetch this from the database.
MODERATORS = {
    "moderator1": {
        "hashed_password": bcrypt.hash("password123"),
    },
    "moderator2": {
        "hashed_password": bcrypt.hash("secure_pass"),
    }
}


class LoginForm(Form):  # Example form for input validation
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.Length(min=8)])


def auth_mod(username, password):
    """Authenticates a moderator."""
    if not username or not password:
        logging.warning("Authentication attempt with empty credentials")
        return False  # Prevent empty credentials

    if username in MODERATORS:
        user_data = MODERATORS[username]
        hashed_password = user_data["hashed_password"]

        if bcrypt.verify(password, hashed_password):
            logging.info(f"User {username} authenticated successfully")
            return True
        else:
            logging.warning(f"Authentication failed for user {username}")
            return False
    else:
        logging.warning(f"Authentication attempt with unknown user {username}")
        return False


def require_auth(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            logging.warning("Unauthorized access attempt")
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """Handles user login."""
    form = LoginForm(request.form)
    if form.validate():
        username = form.username.data
        password = form.password.data

        if username in MODERATORS:
            if auth_mod(username, password):
                session['username'] = username  # Store username in session
                session.permanent = True  # Mark session as permanent
                session.regenerate()  # Regenerate session ID to prevent session fixation
                logging.info(f"User {username} logged in")
                return jsonify({"message": "Login successful"}), 200
            else:
                logging.warning(f"Invalid credentials for user {username}")
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            logging.warning(f"Login attempt with unknown user {username}")
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        logging.warning(f"Invalid login form data: {form.errors}")
        return jsonify({"error": "Invalid input"}), 400


@app.route('/logout')
def logout():
    """Handles user logout."""
    if 'username' in session:
        username = session['username']
        session.pop('username', None)
        logging.info(f"User {username} logged out")
        return jsonify({"message": "Logged out successfully"}), 200
    else:
        return jsonify({"message": "Not logged in"}), 200


@app.route('/check_mod', methods=['GET'])
@require_auth
def check_mod():
    """Checks if the user is a moderator."""
    # Authentication is handled by the require_auth decorator and the session.
    return jsonify({"is_moderator": True}), 200


if __name__ == '__main__':
    #  NEVER use 'adhoc' in production.  Get a real SSL certificate.
    #  Consider using a WSGI server like Gunicorn or uWSGI in production.
    app.run(debug=True, ssl_context='adhoc')  # Enable SSL for local testing

