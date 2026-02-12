from flask import request, current_app, Flask, abort
import logging
import html
import re  # For input validation
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import os  # For secret key and environment variables
import secrets # For generating secure random values

app = Flask(__name__)

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example: 200 requests per day, 50 per hour
)

# Set a strong secret key
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(24) # Get from environment or generate a random one

# Example Authentication (replace with a real authentication system)
# Store hashed passwords!
users = {
    "admin": generate_password_hash(os.environ.get('ADMIN_PASSWORD') or "password123") # Get from environment or use a default
}

def authenticate(username, password):
    if username in users:
        return check_password_hash(users[username], password)
    return False

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return "Authentication required", 401
        return f(*args, **kwargs)
    return decorated

@app.route('/log')
@limiter.limit("5/minute")  # Limit to 5 requests per minute
@requires_auth
def log():
    '''
    Get the "input" from the GET request and log it (with restrictions).
    '''

    user_input = request.args.get('input', '')  # Get the 'input' parameter safely

    # Input Validation (CRITICAL)
    if not re.match(r"^[a-zA-Z0-9\s.,?!-]+$", user_input):  # Example: Allow only alphanumeric characters, spaces, and punctuation
        app.logger.warning("Invalid user input format.  Rejected.")
        abort(400, "Invalid input") # Use abort for cleaner error handling

    # Length Limit
    if len(user_input) > 200:
        app.logger.warning("Input too long. Rejected.")
        abort(400, "Input too long")

    # Sanitize the input to prevent XSS attacks (still important, but not the only defense)
    sanitized_input = html.escape(user_input)

    # Log the sanitized input as an info message, but only the first 100 characters
    app.logger.info(f"User input (truncated): {sanitized_input[:100]}")  # Use f-strings for clarity

    return "Logged", 200  # Indicate success

@app.errorhandler(400)
def bad_request(e):
    app.logger.error(f"Bad Request: {e}")
    return f"Bad Request: {e}", 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', ssl_context='adhoc')  # Never run in debug mode in production!  Force HTTPS for testing

