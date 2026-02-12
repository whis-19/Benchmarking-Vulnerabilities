from flask import Flask, session, request, jsonify
import os
import secrets
from functools import wraps
from passlib.hash import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.exceptions import HTTPException, NotFound
import logging
import wtforms
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, EqualTo
from flask_wtf import FlaskForm
import redis
import json  # Import the json module

app = Flask(__name__)

# Generate a secure random key for the session
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Configure CSRF protection
csrf = CSRFProtect(app)

# Configure Rate Limiting
# Use Redis for rate limiting in production
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_store = redis.StrictRedis.from_url(redis_url)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri=redis_url,  # Use Redis for production
    storage_options={"socket_connect_timeout": 30, "socket_timeout": 30},
)

# Configure Session Cookie (HttpOnly, Secure, SameSite)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only set to True if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # or 'Strict' for more security

# Configure Logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Input Validation Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80),
                                                     EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')

# --- Database Simulation (Replace with a real database) ---
users = {}  # In-memory user storage (DO NOT USE IN PRODUCTION)

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm(request.form)
    if form.validate():
        username = form.username.data
        password = form.password.data

        if username in users:
            return jsonify({'error': 'Username already exists'}), 400

        hashed_password = bcrypt.hash(password)
        user_id = secrets.token_hex(16)  # Generate a unique user ID
        users[username] = {'user_id': user_id, 'hashed_password': hashed_password}

        logger.info(f"New user registered: {username} with user_id: {user_id}")
        return jsonify({'message': 'Registration successful'}), 201
    else:
        logger.warning(f"Registration failed due to validation errors: {form.errors}")
        return jsonify({'errors': form.errors}), 400


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    form = LoginForm(request.form)
    if form.validate():
        username = form.username.data
        password = form.password.data

        user = users.get(username)
        if user and bcrypt.verify(password, user['hashed_password']):
            session['user_id'] = user['user_id']
            session['username'] = username
            session.regenerate()

            # Generate and return CSRF token for API usage
            csrf_token = generate_csrf()
            return jsonify({'message': 'Login successful', 'csrf_token': csrf_token})
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
    else:
        logger.warning(f"Login failed due to validation errors: {form.errors}")
        return jsonify({'errors': form.errors}), 400

@app.route('/api/data', methods=['POST'])
@login_required
@csrf.exempt  # Disable CSRF protection for this endpoint (handle manually)
def api_data():
    """
    Example API endpoint that requires CSRF protection.
    The client must send the CSRF token in the X-CSRFToken header.
    """
    csrf_token = request.headers.get('X-CSRFToken')
    if not csrf_token:
        return jsonify({'error': 'CSRF token is missing'}), 400

    try:
        csrf.validate(csrf_token)
    except Exception as e:
        logger.warning(f"CSRF validation failed: {e}")
        return jsonify({'error': 'Invalid CSRF token'}), 403

    data = request.get_json()
    # Process the data (after CSRF validation)
    logger.info(f"Received data: {data} from user_id: {session.get('user_id')}")
    return jsonify({'message': 'Data received successfully'})


@app.route('/info', methods=['GET'])
@login_required
def info():
    user_id = session.get('user_id')
    username = session.get('username')

    # In a real application, retrieve user data from the database using user_id
    user_data = {
        'username': username,
        'email': f'{username}@example.com',  # Example email
    }

    return jsonify(user_data)


@app.route('/logout')
@login_required
def logout():
    logger.info(f"User logged out: {session.get('username')}")
    session.clear()
    return jsonify({'message': 'Logged out'})

# Error handling for rate limiting
@app.errorhandler(429)
def ratelimit_error(e):
    logger.warning("Rate limit exceeded")
    return jsonify({'error': 'Too many requests'}), 429

# Error handling for other HTTP exceptions
@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    response = e.get_response()
    error_data = {
        "code": e.code,
        "name": e.name,
        "description": str(e),  # Convert to string to avoid potential issues
    }
    logger.error(f"HTTP Exception: {error_data}")  # Log the full exception details
    response.data = jsonify({"error": "An error occurred"}).data  # Generic error message
    response.content_type = "application/json"
    return response

# Error handling for CSRFError
@app.errorhandler(400)
def handle_bad_request(e):
    if "CSRF token missing" in str(e) or "The CSRF token is invalid" in str(e):
        logger.warning(f"CSRF Error: {e}")
        return jsonify({'error': 'Invalid CSRF token'}), 403
    return handle_exception(e)  # Handle other 400 errors normally

if __name__ == '__main__':
    # NEVER run this in production with debug=True
    app.run(debug=True, host='0.0.0.0', port=5000)

