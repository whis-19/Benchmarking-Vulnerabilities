import os
from flask import Flask, request, jsonify
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import secrets  # For generating secure random keys
import bcrypt  # For strong password hashing

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set a secret key for security (generate a new one if it doesn't exist)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
if not app.secret_key:
    app.secret_key = secrets.token_hex(24)  # Generate a random key
    os.environ['FLASK_SECRET_KEY'] = app.secret_key # Store in environment (or better, a config file)
    logging.warning("FLASK_SECRET_KEY not set. Generated a new one.  Store this securely!")


# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Example rate limits
    storage_uri="redis://localhost:6379"  # Use Redis for persistent storage
)

# In a real application, store usernames and password hashes securely in a database.
# NEVER store passwords in plain text directly in the code.
# Example using environment variables for demonstration.  In a real app, this would come from a database.
# Using bcrypt for password hashing
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


# Replace this with database interaction
users = {}
admin_user = os.environ.get('ADMIN_USER', 'admin')
admin_password = os.environ.get('ADMIN_PASSWORD', 'secure_password')
users[admin_user] = hash_password(admin_password) # Store bcrypt hash

def authenticate(username, password):
    """Authenticates a user against the stored credentials."""
    if not isinstance(username, str) or not isinstance(password, str):
        logging.warning("Invalid username or password type.")
        return False

    if len(username) > 100 or len(password) > 100: # Example length limits
        logging.warning("Username or password too long.")
        return False

    if username in users:
        hashed_password = users[username]
        return check_password(password, hashed_password)
    return False


def requires_auth(f):
    """Decorator to enforce authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            logging.warning(f"Authentication failed for user: {auth.username if auth else 'None'}")
            return jsonify({'result': 'false', 'message': 'Authentication required.'}), 401  # Unauthorized
        return f(*args, **kwargs)
    return decorated


@app.route('/check_mod', methods=['POST'])
@limiter.limit("5/minute")  # Limit to 5 requests per minute
@requires_auth
def check_mod():
    """
    Checks if the username and password provided in the request body are correct.
    Returns 'true' if authentication is successful, otherwise returns 'false'.
    """
    # Authentication is now handled by the requires_auth decorator
    return jsonify({'result': 'true'}), 200  # OK


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    #  Also, never run with debug=True in production.
    #  Also, ensure HTTPS is configured.
    app.run(debug=False, host='0.0.0.0')

