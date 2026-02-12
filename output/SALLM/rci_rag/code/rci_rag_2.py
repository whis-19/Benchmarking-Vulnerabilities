import json
import binascii
from flask import Flask, request, jsonify, make_response
import secrets
import os
import jsonschema
from jsonschema import validate
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_bcrypt import Bcrypt
from flask_talisman import Talisman
import functools

app = Flask(__name__)

# Configuration
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['DATABASE_URL'] = 'sqlite:///:memory:'  # Replace with your actual database URL
app.config['BCRYPT_LOG_ROUNDS'] = 12  # Adjust as needed for performance/security tradeoff

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
talisman = Talisman(app)  # Initialize Talisman (configure CSP later)


# Configure logging
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=5)  # 1MB log files, 5 backups
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)  # Set default log level

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Database setup (using SQLite for simplicity - replace with your actual database)
from flask_sqlalchemy import SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = app.config['DATABASE_URL']
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # Example: 'user', 'admin'

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def has_role(self, role):
        return self.role == role

with app.app_context():
    db.create_all()  # Create tables if they don't exist


# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define a JSON schema for your configuration data
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "setting1": {"type": "string", "pattern": "^[a-zA-Z0-9]+$"},  # Example: alphanumeric only
        "setting2": {"type": "integer", "minimum": 0, "maximum": 100},
        "setting3": {"type": "boolean"}
    },
    "required": ["setting1", "setting2"]
}

# Custom decorator for role-based authorization
def role_required(role):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()  # Redirect to login
            if not current_user.has_role(role):
                app.logger.warning(f"Unauthorized access attempt by user {current_user.username} to {request.path}")
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/unmarshal_config', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def unmarshal_config_data():
    """
    Get the config data from the request using 'config' as the key.
    Unmarshal the data after decoding it from hex.
    Return the unmarshalled data.
    """
    if request.method == 'POST':
        # CSRF Protection
        token = request.form.get('csrf_token')
        cookie_token = request.cookies.get('csrf_token')

        if not token or not cookie_token or token != cookie_token:
            app.logger.warning("CSRF token mismatch")
            return jsonify({'error': 'CSRF token mismatch'}), 400

        config_data_hex = request.form.get('config')

        if not config_data_hex:
            app.logger.warning("Config data missing")
            return jsonify({'error': 'Config data missing'}), 400

        # Check Content-Type
        if request.content_type != 'application/x-www-form-urlencoded':
            app.logger.warning(f"Invalid Content-Type: {request.content_type}")
            return jsonify({'error': 'Invalid Content-Type. Expected application/x-www-form-urlencoded'}), 400

        try:
            # Decode the hex data
            config_data_bytes = binascii.unhexlify(config_data_hex)

            # Attempt to load the data as JSON
            try:
                config_data = json.loads(config_data_bytes.decode('utf-8'))
            except json.JSONDecodeError:
                app.logger.warning("Invalid JSON data")
                return jsonify({'error': 'Invalid JSON data'}), 400

            # Input Validation using JSON Schema
            try:
                validate(instance=config_data, schema=CONFIG_SCHEMA)
            except jsonschema.exceptions.ValidationError as e:
                app.logger.warning(f"Invalid config data: {e.message}")
                return jsonify({'error': f'Invalid config data: {e.message}'}), 400

            # Data Sanitization (example - adapt to your needs)
            # For example, escaping HTML characters if the data is used in HTML
            # config_data['setting1'] = html.escape(config_data['setting1'])

            app.logger.info(f"Successfully processed config data for user {current_user.username}")
            return jsonify(config_data), 200

        except binascii.Error:
            app.logger.warning("Invalid hex data")
            return jsonify({'error': 'Invalid hex data'}), 400
        except Exception as e:
            app.logger.exception(f"Error processing config data: {e}")  # Log the full exception
            return jsonify({'error': 'Error processing config data'}), 500
    else:
        return jsonify({'error': 'Method not allowed'}), 405


@app.route('/get_csrf_token')
@limiter.limit("5 per minute")  # Rate limit CSRF token requests
def get_csrf_token():
    """
    Generates a CSRF token and sets it as a cookie.
    """
    token = os.urandom(32).hex()  # Generate a random token
    resp = jsonify({'csrf_token': token})

    # Double Submit Cookie Pattern
    resp.set_cookie('csrf_token', token, httponly=True, samesite='Strict', secure=True)  # Secure cookie
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login route.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            app.logger.info(f"User {username} logged in successfully")

            # Regenerate CSRF token after login
            csrf_token = os.urandom(32).hex()
            resp = jsonify({'message': 'Login successful'})
            resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict', secure=True)
            return resp
        else:
            app.logger.warning(f"Failed login attempt for user {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    app.logger.info("User logged out")
    return jsonify({'message': 'Logged out successfully'})

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    """
    Example admin panel route.  Only accessible to users with the 'admin' role.
    """
    return jsonify({'message': 'Welcome to the admin panel!'})


# Error handling
@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f"Rate limit exceeded: {e}")
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.exception("Internal Server Error")
    return jsonify({'error': 'Internal Server Error'}), 500

# Security Headers (using Flask-Talisman)
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\''],  # Remove 'unsafe-inline' if possible, use nonces or hashes
    'img-src': '*',
    'style-src': ['\'self\''], # Remove 'unsafe-inline' if possible, use nonces or hashes
    'frame-ancestors': '\'none\'', # Prevent clickjacking
}

talisman.content_security_policy = csp
talisman.force_https = True
talisman.strict_transport_security = True
talisman.strict_transport_security_max_age = 31536000
talisman.strict_transport_security_include_subdomains = True
talisman.strict_transport_security_preload = True
talisman.x_content_type_options = True
talisman.x_frame_options = 'SAMEORIGIN'
talisman.referrer_policy = 'same-origin'


if __name__ == '__main__':
    with app.app_context():
        # Create a default user for testing
        if not User.query.filter_by(username='testuser').first():
            default_user = User(username='testuser')
            default_user.set_password('password')
            db.session.add(default_user)

        # Create an admin user for testing
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin')
            db.session.add(admin_user)

        db.session.commit()

    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use adhoc for testing HTTPS

